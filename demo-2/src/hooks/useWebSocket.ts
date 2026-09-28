"use client";

import { useEffect, useRef, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useUIStore } from '@/store/uiStore';
import { useTopologyStore } from '@/store/topologyStore';
import { useIncidentStore } from '@/store/incidentStore';
import { usePredictionStore } from '@/store/predictionStore';
import { useDeceptionStore } from '@/store/deceptionStore';

interface WSEvent {
  event: string;
  timestamp: string;
  incident_id?: string;
  payload: any;
}

export function useWebSocket(incidentId?: string) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 10;
  const baseReconnectDelay = 1000;
  
  const queryClient = useQueryClient();
  const { addNotification } = useUIStore();
  const { updateNode, addNode, addPredictionEdge, removePredictionEdge } = useTopologyStore();
  const { setActiveIncident, updateIncident } = useIncidentStore();
  const { setForecast, setLatestDecision } = usePredictionStore();
  const { addInteraction } = useDeceptionStore();

  const handleMessage = useCallback((message: WSEvent) => {
    console.log('WS Event:', message.event, message.payload);
    
    switch (message.event) {
      case 'model_decision_executed': {
        const { model_decision, forecast } = message.payload || {};
        if (model_decision) {
          setLatestDecision(model_decision);
        }
        if (forecast) {
          setForecast(forecast);
          queryClient.setQueryData(['forecast', message.incident_id], forecast);
        }
        addNotification({
          type: 'warning',
          message: `World Model: Triggered ${model_decision?.action || 'DECEPTION_DIVERT'} (${model_decision?.risk_reduction_pct || 0}% risk reduced)`,
        });
        break;
      }
      case 'node_added': {
        const node = message.payload?.node;
        if (!node) break;
        addNode({
          id: node.id,
          label: node.label,
          asset_id: node.asset_id,
          asset_type: node.asset_type,
          zone: node.zone,
          status: node.status,
          threatScore: node.threat_score ?? node.threatScore ?? 0,
          criticality: node.criticality,
          position: node.position || undefined,
          metadata: node.metadata || {},
        });
        addNotification({
          type: 'info',
          message: `Device enrolled & added to topology: ${node.label}`,
        });
        break;
      }

      case 'asset_status_changed': {
        const { asset_id, asset_name, old_status, new_status, threat_score } = message.payload;
        updateNode(asset_id, { status: new_status, threatScore: threat_score });        
        // Update cache
        queryClient.setQueryData(['topology'], (old: any) => {
          if (!old) return old;
          return {
            ...old,
            nodes: old.nodes.map((n: any) => 
              n.id === asset_id ? { ...n, status: new_status, threatScore: threat_score } : n
            ),
          };
        });
        
        addNotification({ 
          type: new_status === 'compromised' ? 'error' : 'warning', 
          message: `${asset_name} status changed to ${new_status}` 
        });
        break;
      }
      
      case 'prediction_generated': {
        const { forecast } = message.payload;
        setForecast(forecast);
        queryClient.setQueryData(['forecast', message.incident_id], forecast);
        addNotification({ type: 'info', message: 'New prediction available' });
        break;
      }
      
      case 'forecast_updated': {
        const { forecast } = message.payload;
        setForecast(forecast);
        queryClient.setQueryData(['forecast', message.incident_id], forecast);
        break;
      }
      
      case 'incident_created': {
        const { incident } = message.payload;
        // Refresh incidents list
        queryClient.invalidateQueries({ queryKey: ['incidents'] });
        addNotification({ type: 'error', message: `New incident: ${incident.title}` });
        break;
      }
      
      case 'incident_updated': {
        const { incident_id, updates } = message.payload;
        queryClient.invalidateQueries({ queryKey: ['incidents'] });
        queryClient.invalidateQueries({ queryKey: ['incident', incident_id] });
        break;
      }
      
      case 'honeypot_deployed': {
        const { deployment_id, honeypot_types, target_assets } = message.payload;
        queryClient.invalidateQueries({ queryKey: ['deception'] });
        addNotification({ type: 'info', message: `Honeynet deployed: ${honeypot_types.join(', ')}` });
        break;
      }
      
      case 'honeypot_interaction': {
        const { deployment_id, interaction } = message.payload;
        addInteraction(deployment_id, interaction);
        queryClient.invalidateQueries({ queryKey: ['deception', deployment_id] });
        addNotification({ type: 'warning', message: `Honeypot interaction: ${interaction.action} from ${interaction.source_ip}` });
        break;
      }
      
      case 'host_isolated': {
        const { asset_id, asset_name, isolation_level } = message.payload;
        updateNode(asset_id, { status: 'contained', containmentLevel: isolation_level });
        addNotification({ type: 'info', message: `${asset_name} isolated (${isolation_level})` });
        break;
      }
      
      case 'host_restored': {
        const { asset_id } = message.payload;
        updateNode(asset_id, { status: 'normal', containmentLevel: 'none', threatScore: 0 });
        addNotification({ type: 'success', message: 'Asset restored' });
        break;
      }
      
      case 'snapshot_created': {
        addNotification({ type: 'info', message: `Configuration snapshot created: ${message.payload.label}` });
        break;
      }
      
      case 'timeline_updated': {
        queryClient.invalidateQueries({ queryKey: ['timeline', message.incident_id] });
        break;
      }
      
      default:
        console.log('Unhandled WS event:', message.event);
    }
  }, [updateNode, addNode, addPredictionEdge, removePredictionEdge, setActiveIncident, updateIncident, setForecast, addInteraction, addNotification, queryClient]);

  const connectRef = useRef<() => void>(() => {});

  const scheduleReconnect = useCallback(() => {
    if (reconnectAttempts.current >= maxReconnectAttempts) {
      console.log('Max reconnect attempts reached');
      return;
    }
    
    const delay = Math.min(baseReconnectDelay * Math.pow(2, reconnectAttempts.current), 30000);
    reconnectTimeoutRef.current = setTimeout(() => {
      reconnectAttempts.current++;
      connectRef.current();
    }, delay);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    
    // Next's development rewrite proxies HTTP but does not reliably retain the
    // WebSocket upgrade. Keep the host dynamic for LAN clients and target the
    // backend's published socket port directly.
    const dynamicBackendWs = typeof window === 'undefined'
      ? 'ws://localhost:8000/api/v1/topology/live'
      : `ws://${window.location.hostname}:8000/api/v1/topology/live`;
    const incidentQuery = incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : '';
    const wsUrl = `${process.env.NEXT_PUBLIC_WS_URL || dynamicBackendWs}${incidentQuery}`;
    wsRef.current = new WebSocket(wsUrl);
    
    wsRef.current.onopen = () => {
      console.log('WebSocket connected');
      reconnectAttempts.current = 0;
      
      // Subscribe to events
      const socket = wsRef.current;
      if (!socket || socket.readyState !== WebSocket.OPEN) return;
      try {
        socket.send(JSON.stringify({
          type: 'subscribe',
          events: [
            'node_added',
            'asset_status_changed',
            'prediction_generated',
            'forecast_updated',
            'incident_created',
            'incident_updated',
            'honeypot_deployed',
            'honeypot_interaction',
            'host_isolated',
            'host_restored',
            'snapshot_created',
            'timeline_updated',
          ],
        }));
      } catch (error) {
        console.error('Failed to subscribe to websocket events:', error);
        scheduleReconnect();
      }
    };
    
    wsRef.current.onclose = () => {
      console.log('WebSocket closed');
      if (wsRef.current?.readyState !== WebSocket.OPEN) {
        wsRef.current = null;
      }
      scheduleReconnect();
    };
    
    wsRef.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      scheduleReconnect();
    };
  }, [incidentId, scheduleReconnect]);

  connectRef.current = connect;

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (flushTimerRef.current) {
      clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
  }, []);

  const eventQueueRef = useRef<WSEvent[]>([]);
  const flushTimerRef = useRef<NodeJS.Timeout | null>(null);

  const flushQueue = useCallback(() => {
    const queue = eventQueueRef.current;
    if (queue.length === 0) return;
    eventQueueRef.current = [];
    for (const msg of queue) {
      handleMessage(msg);
    }
  }, [handleMessage]);

  const queueMessage = useCallback((message: WSEvent) => {
    eventQueueRef.current.push(message);
    if (!flushTimerRef.current) {
      flushTimerRef.current = setTimeout(() => {
        flushTimerRef.current = null;
        flushQueue();
      }, 50);
    }
  }, [flushQueue]);

  useEffect(() => {
    connect();
    
    return () => {
      disconnect();
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect, disconnect]);

  // Handle reconnection on error/close
  useEffect(() => {
    const ws = wsRef.current;
    if (!ws) return;
    
    const handleError = () => {
      console.log('WebSocket error, scheduling reconnect');
      scheduleReconnect();
    };
    
    const handleClose = () => {
      console.log('WebSocket closed, scheduling reconnect');
      scheduleReconnect();
    };
    
    ws.addEventListener('error', handleError);
    ws.addEventListener('close', handleClose);
    
    return () => {
      ws.removeEventListener('error', handleError);
      ws.removeEventListener('close', handleClose);
    };
  }, [scheduleReconnect]);

  // Handle incoming messages with debounced batch queue
  useEffect(() => {
    const ws = wsRef.current;
    if (!ws) return;
    
    const onMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        queueMessage(data);
      } catch (e) {
        console.error('Failed to parse WS message:', e);
      }
    };
    
    ws.addEventListener('message', onMessage);
    return () => ws.removeEventListener('message', onMessage);
  }, [queueMessage]);

  return { connect, disconnect };
}
