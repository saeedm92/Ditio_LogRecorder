make
sudo adb push scripts/load_log_recorder.sh /data/local
sudo adb push scripts/run_config_app_start.sh /data/local
sudo adb push scripts/run_config_app_stop.sh /data/local
sudo adb push log_recorder.ko /data/local
sudo adb push config_app /data/local/

