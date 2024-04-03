
export default () => ({
    DB_HOST: process.env.DB_HOST,
    DB_NAME: process.env.DB_NAME,
    ACCESS_TOKEN_SECRET: process.env.ACCESS_TOKEN_SECRET,
    REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,
  });