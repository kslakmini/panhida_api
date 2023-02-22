module.exports = {
  apps: [
    {
      name: 'API',
      script: './app.js',
      watch: true,
      env: {
        NODE_ENV: process.env.NODE_ENV,
        PORT: process.env.PORT,
        JWT_KEY: process.env.JWT_KEY,
        DB_USER: process.env.DB_USER,
        DB_PASSWORD: process.env.DB_PASSWORD,
        DB_NAME: process.env.DB_NAME,
        REFRESH_KEY: process.env.REFRESH_KEY,
        CLIENT_URL: process.env.CLIENT_URL,
        SENDGRID_API_KEY: process.env.SENDGRID_API_KEY,
      },
    },
  ],
};
