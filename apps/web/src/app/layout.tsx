import './globals.css';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'Assay',
  description: 'Cryptographic bill of materials with an inspectable migration ranking',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
