# llm-detection

Update .env.example with your OPENAI API key


Data flow:

1. test.py — LLM + Wappalyzer, produces two things: the compiled signature DB (detected_technologies*.json) and the in-session Wappalyzer ground truth per domain.
2. detect_technologies_regex.py — takes that signature DB, re-scans the domains fresh with zero LLM calls, and produces the actual algorithmic detections (regex_detected_results*.json). This is the "no-LLM" step.
3. precision_ground_truth.py — scores step 2's output against step 1's ground truth. It never touches the LLM or a live signature-generation pass itself; it just compares two JSON files.
