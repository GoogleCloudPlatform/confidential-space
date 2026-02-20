import time
import datetime

# Get the current time
start_time = datetime.datetime.now()
print(f"Starting script at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

print(f"Printing workload test version A!")

# Calculate the duration in seconds
sleep_duration_seconds = 5  # 5 seconds

print(f"Now sleeping for {sleep_duration_seconds} seconds ...")

# Pause execution
time.sleep(sleep_duration_seconds)

# Get the time after sleeping
end_time = datetime.datetime.now()
print(f"Finished sleeping at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
