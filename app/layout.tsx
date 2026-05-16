import type { Metadata } from 'next';
import { Sora, Inter, Mulish } from 'next/font/google';
import './globals.css';

// next/font self-hosts Google Fonts at build time. This eliminates layout
// shift, removes the render-blocking <link> requests, and avoids handing
// users' browsers off to fonts.googleapis.com on every page load.
//
// Each family exposes a CSS variable (--font-sora, --font-inter, --font-mulish)
// that globals.css references through its semantic tokens.
const sora = Sora({
  subsets: ['latin'],
  variable: '--font-sora',
  weight: ['400', '500', '600', '700', '800'],
  display: 'swap',
});

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  weight: ['400', '500', '600', '700'],
  display: 'swap',
});

const mulish = Mulish({
  subsets: ['latin'],
  variable: '--font-mulish',
  weight: ['400', '500', '600', '700'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Cubo Fraud Engine',
  description: 'Herramienta interna de análisis de fraude para Cubo Pago',
  robots: { index: false, follow: false },
  icons: {
    icon: '/cubo-iso.png',
    apple: '/cubo-iso.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className={`${sora.variable} ${inter.variable} ${mulish.variable}`}>
      <body>{children}</body>
    </html>
  );
}
