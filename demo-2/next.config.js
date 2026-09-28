/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    optimizePackageImports: ['lucide-react', '@radix-ui/react-icons'],
  },
  images: {
    domains: ['localhost'],
  },
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: 'http://backend:8000/api/v1/:path*',
      },
    ];
  },
  async redirects() {
    return [
      { source: '/command-center', destination: '/', permanent: false },
      { source: '/command-centre', destination: '/', permanent: false },
      { source: '/admin', destination: '/', permanent: false },
    ];
  },
};

module.exports = nextConfig;
