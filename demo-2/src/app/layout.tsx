import { Providers } from './providers';
import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Predictive Cyber Defence',
  description: 'AI-powered network attack forecasting and automated response',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className="bg-[var(--bg-primary)] text-[var(--text-primary)] antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}