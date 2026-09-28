"""
Training script for World Model.
"""
import os
import sys
import hydra
from omegaconf import DictConfig, OmegaConf
import torch
import pytorch_lightning as pl
from pytorch_lightning.callbacks import ModelCheckpoint, EarlyStopping, LearningRateMonitor
from pytorch_lightning.loggers import MLflowLogger, WandbLogger

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import WorldModel, create_world_model
from training.data_module import NetworkDataModule
from training.lightning_module import WorldModelLightning


@hydra.main(version_base=None, config_path="../configs", config_name="model_config")
def train(cfg: DictConfig) -> None:
    """Main training function."""
    
    # Print config
    print(OmegaConf.to_yaml(cfg))
    
    # Set seed for reproducibility
    pl.seed_everything(cfg.get("seed", 42), workers=True)
    
    # Create model
    model_config = OmegaConf.to_container(cfg.model, resolve=True)
    model = create_world_model(model_config)
    
    # Wrap in Lightning module
    lightning_model = WorldModelLightning(model, cfg.training, cfg.evaluation)
    
    # Data module
    data_module = NetworkDataModule(cfg.data)
    
    # Callbacks
    callbacks = [
        ModelCheckpoint(
            dirpath=cfg.paths.checkpoints,
            filename="world-model-{epoch:02d}-{val_loss:.4f}",
            monitor=cfg.training.monitor,
            mode=cfg.training.mode,
            save_top_k=cfg.training.save_top_k,
            save_last=cfg.training.save_last,
            every_n_epochs=cfg.training.every_n_epochs,
        ),
        EarlyStopping(
            monitor=cfg.training.early_stopping_metric,
            patience=cfg.training.early_stopping_patience,
            mode=cfg.training.early_stopping_mode,
        ),
        LearningRateMonitor(logging_interval="step"),
    ]
    
    # Loggers
    loggers = []
    
    if cfg.get("mlflow", {}).get("enabled", False):
        loggers.append(MLflowLogger(
            experiment_name=cfg.mlflow.experiment_name,
            tracking_uri=cfg.mlflow.tracking_uri,
        ))
    
    if cfg.get("wandb", {}).get("enabled", False):
        loggers.append(WandbLogger(
            project=cfg.wandb.project,
            name=cfg.wandb.run_name,
            config=OmegaConf.to_container(cfg, resolve=True),
        ))
    
    # Trainer
    trainer = pl.Trainer(
        max_epochs=cfg.training.epochs,
        accelerator=cfg.training.accelerator,
        devices=cfg.training.devices,
        precision=cfg.training.precision,
        strategy=cfg.training.strategy,
        callbacks=callbacks,
        logger=loggers,
        log_every_n_steps=cfg.training.log_every_n_steps,
        val_check_interval=cfg.training.val_check_interval,
        limit_val_batches=cfg.training.limit_val_batches,
        limit_test_batches=cfg.training.limit_test_batches,
        gradient_clip_val=cfg.model.regularization.gradient_clip,
        accumulate_grad_batches=cfg.training.gradient_accumulation_steps,
        enable_progress_bar=True,
        enable_model_summary=True,
    )
    
    # Train
    trainer.fit(lightning_model, datamodule=data_module)
    
    # Test
    trainer.test(lightning_model, datamodule=data_module, ckpt_path="best")
    
    # Export to ONNX
    if cfg.inference.use_onnx:
        export_onnx(lightning_model.model, cfg)


def export_onnx(model: WorldModel, cfg: DictConfig) -> None:
    """Export model to ONNX format."""
    import onnx
    import onnxruntime as ort
    
    model.eval()
    
    # Create wrapper for ONNX export
    class ONNXWrapper(torch.nn.Module):
        def __init__(self, model):
            super().__init__()
            self.model = model
            
        def forward(self, node_features, edge_index, edge_attr, batch, 
                   host_features, host_mask, traffic_features,
                   asset_embeddings, asset_mask):
            current_state = {
                "node_features": node_features,
                "edge_index": edge_index,
                "edge_attr": edge_attr,
                "batch": batch,
                "host_features": host_features,
                "host_mask": host_mask,
                "traffic_features": traffic_features,
            }
            output = self.model.predict(
                current_state=current_state,
                asset_embeddings=asset_embeddings,
                asset_mask=asset_mask,
            )
            return output.stage_probs, output.target_probs
    
    wrapper = ONNXWrapper(model)
    
    # Dummy inputs
    batch_size = 1
    dummy_inputs = (
        torch.randn(batch_size, 50, cfg.model.node_input_dim),
        torch.randint(0, 50, (batch_size, 2, 200)),
        torch.randn(batch_size, 200, cfg.model.edge_input_dim),
        torch.arange(batch_size).repeat_interleave(50),
        torch.randn(batch_size, 50, cfg.model.host_input_dim),
        torch.ones(batch_size, 50, dtype=torch.bool),
        torch.randn(batch_size, 20, cfg.model.traffic_input_dim),
        torch.randn(batch_size, 50, cfg.model.hidden_dim),
        torch.ones(batch_size, 50, dtype=torch.bool),
    )
    
    # Export
    onnx_path = os.path.join(cfg.paths.checkpoints, "world_model.onnx")
    torch.onnx.export(
        wrapper,
        dummy_inputs,
        onnx_path,
        export_params=True,
        opset_version=cfg.inference.get("onnx_opset", 17),
        do_constant_folding=True,
        input_names=[
            "node_features", "edge_index", "edge_attr", "batch",
            "host_features", "host_mask", "traffic_features",
            "asset_embeddings", "asset_mask"
        ],
        output_names=["stage_probs", "target_probs"],
        dynamic_axes={
            "node_features": {0: "batch", 1: "nodes"},
            "edge_index": {0: "batch", 2: "edges"},
            "edge_attr": {0: "batch", 1: "edges"},
            "host_features": {0: "batch", 1: "hosts"},
            "traffic_features": {0: "batch", 1: "seq_len"},
            "asset_embeddings": {0: "batch", 1: "assets"},
        },
    )
    
    # Optimize with ONNX Simplifier
    try:
        import onnxsim
        model_onnx = onnx.load(onnx_path)
        model_simp, check = onnxsim.simplify(model_onnx)
        assert check, "Simplified ONNX model could not be validated"
        onnx.save(model_simp, onnx_path)
        print(f"ONNX model saved and optimized to {onnx_path}")
    except ImportError:
        print(f"ONNX model saved to {onnx_path} (onnxsim not installed, skipping optimization)")
    
    # Verify with ONNX Runtime
    ort_session = ort.InferenceSession(onnx_path)
    ort_inputs = {name: inp.numpy() for name, inp in zip([
        "node_features", "edge_index", "edge_attr", "batch",
        "host_features", "host_mask", "traffic_features",
        "asset_embeddings", "asset_mask"
    ], dummy_inputs)}
    
    ort_outputs = ort_session.run(None, ort_inputs)
    print(f"ONNX Runtime verification successful. Output shapes: {[o.shape for o in ort_outputs]}")


if __name__ == "__main__":
    train()