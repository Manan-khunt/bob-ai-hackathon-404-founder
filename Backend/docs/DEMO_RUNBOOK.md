# IMMUNE-NET Demo Runbook

## Start

```powershell
python -m pip install -r requirements.txt
python run_simulation.py
```

In a second terminal, open `http://localhost:8000/docs` and `http://localhost:5173/`.

## Deterministic injection

```powershell
python -c "from attacker.attack import run_attack; print(run_attack('http://localhost:8000', 'node-beta', 'worm_ravage'))"
```

Inspect `GET /incidents`, `GET /antibodies`, and the HUD WebSocket at `/ws/hud`.

## Rebuild baseline model

Collect healthy frames through `POST /telemetry`, then call `POST /rebuild_model`.

## Reset

Use the existing explicit `POST /api/demo/reset` endpoint before repeating a demo.
