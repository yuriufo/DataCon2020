#!/bin/bash

start_time=$(date +%s)

python run.py
python test.py

end_time=$(date +%s)
cost_time=$[ $end_time-$start_time ]
echo "Time is out. $(($cost_time/60))min $(($cost_time%60))s"
