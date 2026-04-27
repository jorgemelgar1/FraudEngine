import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Cubo Fraud Engine',
  description: 'Internal fraud analysis tool for Cubo Pago',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
