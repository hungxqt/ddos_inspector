# snort_stats_exporter.py
# Prometheus exporter for Snort 3 statistics (snort.stats)

from flask import Flask, Response

app = Flask(__name__)

@app.route("/metrics")
def metrics():
    output = []
    try:
        with open("snort.stats", "r") as f:
            for line in f:
                if ":" in line:
                    key, val = line.strip().split(":")
                    key = key.replace(".", "_").strip()
                    val = val.strip()
                    try:
                        float(val)
                        output.append(f"snort_{key} {val}")
                    except:
                        continue
    except FileNotFoundError:
        output.append("# snort.stats not found")

    return Response("\n".join(output), mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9092)
