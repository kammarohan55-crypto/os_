#!/bin/bash
# Complete Test Suite for OS Sandbox
# Shows CPU usage and all metrics

echo "========================================="
echo "OS SANDBOX - COMPLETE TEST SUITE"
echo "========================================="
echo ""

# Navigate to project root
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project

# Clean old logs
echo "🧹 Cleaning old logs..."
rm -f logs/*.json
echo ""

echo "========================================="
echo "TEST 1: Normal Execution (STRICT)"
echo "========================================="
./runner/launcher --profile=STRICT /bin/echo "Hello World"
sleep 1
echo ""

echo "========================================="
echo "TEST 2: List Files (LEARNING)"
echo "========================================="
./runner/launcher --profile=LEARNING /bin/ls -la
sleep 1
echo ""

echo "========================================="
echo "TEST 3: Short Sleep (STRICT)"
echo "========================================="
./runner/launcher --profile=STRICT /bin/sleep 0.3
sleep 1
echo ""

echo "========================================="
echo "TEST 4: CPU Hog (LEARNING - Will Auto-Kill)"
echo "========================================="
echo "Expected: Dynamic policy kills after ~2 seconds"
timeout 5 ./runner/launcher --profile=LEARNING samples/cpu_hog || true
sleep 1
echo ""

echo "========================================="
echo "TEST 5: Fork Bomb (STRICT - Blocked)"
echo "========================================="
echo "Expected: SIGSYS (syscall violation)"
./runner/launcher --profile=STRICT samples/fork_bomb || true
sleep 1
echo ""

echo "========================================="
echo "RESULTS SUMMARY"
echo "========================================="
echo ""
echo "📊 Total Logs Created:"
ls -1 logs/ | wc -l
echo ""

echo "📈 CPU Usage Per Test:"
echo "----------------------------------------"
for logfile in logs/*.json; do
    if [ -f "$logfile" ]; then
        program=$(jq -r '.program' "$logfile" | xargs basename)
        profile=$(jq -r '.profile' "$logfile")
        peak_cpu=$(jq -r '.summary.peak_cpu' "$logfile")
        runtime=$(jq -r '.summary.runtime_ms' "$logfile")
        exit_reason=$(jq -r '.summary.exit_reason' "$logfile")
        
        printf "%-20s | %-15s | CPU: %3s%% | Runtime: %5sms | %s\n" \
            "$program" "$profile" "$peak_cpu" "$runtime" "$exit_reason"
    fi
done
echo ""

echo "========================================="
echo "DETAILED VIEW: Latest Run"
echo "========================================="
latest=$(ls -t logs/*.json | head -1)
if [ -f "$latest" ]; then
    echo "File: $(basename $latest)"
    echo ""
    jq '{
        program: .program,
        profile: .profile,
        timeline: {
            samples: (.timeline.time_ms | length),
            cpu_timeline: .timeline.cpu_percent,
            memory_timeline: .timeline.memory_kb
        },
        summary: .summary
    }' "$latest"
fi
echo ""

echo "========================================="
echo "NEXT STEPS"
echo "========================================="
echo "1. Start dashboard:"
echo "   cd dashboard && python3 app.py"
echo ""
echo "2. Open browser:"
echo "   http://localhost:5000"
echo ""
echo "3. Test API:"
echo "   curl -s http://localhost:5000/api/stats | python3 -m json.tool"
echo ""
