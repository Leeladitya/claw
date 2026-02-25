# community_data/ — Arena Decision Exports

## What This Is (for everyone)

When people play the AGORA Decision Arena game and click "Export to AGORA," they download a JSON file containing every decision they made, every argument that survived, and their governance score. Those JSON files go here.

Once there are enough playthroughs, the SDAM model (`server/sdam_model.py`) can analyze them all at once — finding which decision strategies the community prefers, which ones score highest, and where people disagree most.

## How to Contribute Your Playthrough

1. Play the Arena game at [saatvix.com/arena](https://saatvix.com/arena.html)
2. Click "Export to AGORA" at the end
3. A file like `agora-arena-1707912345.json` downloads
4. Drop it in this folder
5. Run the analysis:

```bash
python -c "
from server.sdam_model import batch_analyze_exports
results = batch_analyze_exports('community_data/')
import json
print(json.dumps(results, indent=2))
"
```

## What the Data Looks Like

Each export contains:
- `scenario_id` — which scenario was played
- `decisions` — every choice at every stage
- `scores` — governance scores across 5 dimensions
- `arguments_final` — the final state of the argumentation framework
- `played_at` — when the game was completed

## How it Feeds Into SDAM

The `load_arena_export()` function in `server/sdam_model.py` converts game exports into Powell's SDAM format:
- Your decisions become x_t (decision variables)
- The scenario stages map to S_t → W_{t+1} → S_{t+1} (state transitions)
- Your scores become C(S_t, x_t) (contribution function evaluations)

With enough data, we can run policy search to find the community's optimal governance strategy — the set of decision rules that produce the highest scores across the most scenarios.
