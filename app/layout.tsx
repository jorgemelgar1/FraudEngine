import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Cubo Fraud Engine',
  description: 'Internal fraud analysis tool for Cubo Pago',
  robots: { index: false, follow: false },
  icons: {
    icon: '/cubo-iso.png',
    apple: '/cubo-iso.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&family=Mulish:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
