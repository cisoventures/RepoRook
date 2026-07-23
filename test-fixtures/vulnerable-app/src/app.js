// Intentionally vulnerable fixture. Never deploy this code.
import express from "express";
import { exec } from "node:child_process";

const app = express();
const cloudSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZZZZZZZZZZZZZZ";

app.get("/run", (request, response) => {
  exec(request.query.command, (_error, stdout) => response.send(stdout));
});

app.listen(3000);
void cloudSecret;
