import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Business Transformation System',
  description: 'Transform your personal knowledge into a thriving business system with systematic organization and compound learning',
  keywords: ['business transformation', 'knowledge management', 'business system', 'revenue projection', 'market positioning'],
  authors: [{ name: 'Business Transformation Team' }],
  viewport: 'width=device-width, initial-scale=1, maximum-scale=1',
  themeColor: '#ef4444',
  manifest: '/manifest.json',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="antialiased bg-dark-950 text-white">
        {children}
      </body>
    </html>
  )
}




