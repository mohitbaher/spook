const express = require("express");

const app = express();
app.get("/", (req, res) =>
  res.send("<h1>Ofrenda</h1><p>A candle for the ones we remember. 🕯️</p>")
);
app.listen(3000, () => console.log("Ofrenda glowing on http://localhost:3000"));
