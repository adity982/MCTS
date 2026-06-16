import express from "express";

export const startSseTransport = () => {
  const app = express();
  app.listen(3001);
};
