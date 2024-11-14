export default () => ({
  database: {
    connectionString: process.env.DATABASE_CONNECTION_STRING,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
  },
});
