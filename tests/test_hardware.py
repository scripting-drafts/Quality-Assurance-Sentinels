"""Tests for hardware-tier parsers."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentinels import config, hardware


class AerTests(unittest.TestCase):
    def test_counts_are_summed(self):
        text = "TOTAL_ERR_COR 4\nTOTAL_ERR_FATAL 1\n"
        self.assertEqual(hardware.parse_aer_text(text),
                         {"TOTAL_ERR_COR": 4, "TOTAL_ERR_FATAL": 1})


class EdacTests(unittest.TestCase):
    def test_ue_produces_critical_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            mc = Path(tmp) / "mc0"
            mc.mkdir()
            (mc / "ce_count").write_text("7")
            (mc / "ue_count").write_text("2")
            (mc / "ce_noinfo_count").write_text("0")
            (mc / "ue_noinfo_count").write_text("0")
            items, findings = hardware.parse_edac(tmp)
        self.assertEqual(items["mc0/ue_count"], 2)
        self.assertIn("hardware.edac.ue", {f["rule"] for f in findings})


class RequiredSourceTests(unittest.TestCase):
    def test_host_scoped_contract_overrides_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hardware-sources.json"
            path.write_text(json.dumps({
                "required_sources": ["ras", "storage", "vendor"],
                "not_applicable": {"bmc": "no BMC"},
            }))
            old = config.HARDWARE_SOURCES_PATH
            config.HARDWARE_SOURCES_PATH = path
            try:
                required = hardware.required_sources()
            finally:
                config.HARDWARE_SOURCES_PATH = old
        self.assertEqual(required, ("ras", "storage", "vendor"))

    def test_vendor_cannot_be_scoped_away(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hardware-sources.json"
            path.write_text(json.dumps({"required_sources": ["ras", "storage"]}))
            old = config.HARDWARE_SOURCES_PATH
            config.HARDWARE_SOURCES_PATH = path
            try:
                required = hardware.required_sources()
            finally:
                config.HARDWARE_SOURCES_PATH = old
        self.assertEqual(required, ("ras", "storage", "vendor"))


class StorageTests(unittest.TestCase):
    def test_smart_json_metrics(self):
        data = {
            "model_name": "Disk",
            "smart_status": {"passed": False},
            "ata_smart_attributes": {"table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 3}},
                {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 2}},
            ]},
        }
        metrics = hardware.parse_smart_json(data)
        self.assertFalse(metrics["smart_passed"])
        self.assertEqual(metrics["reallocated"], 3)
        self.assertEqual(metrics["pending"], 2)

    def test_nvme_json_metrics(self):
        metrics = hardware.parse_nvme_json({
            "critical_warning": 0, "temperature": 44,
            "available_spare": 100, "percentage_used": 4,
            "media_errors": 0, "num_err_log_entries": 1,
        })
        self.assertEqual(metrics["temperature_c"], 44)
        self.assertEqual(metrics["available_spare"], 100)


class StorageHandoffTests(unittest.TestCase):
    def test_root_handoff_is_parsed_without_device_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "handoff.json"
            path.write_text(json.dumps({
                "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "devices": {
                    "nvme0n1": {
                        "smartctl": {
                            "model_name": "Test NVMe",
                            "smart_status": {"passed": True},
                            "temperature": {"current": 45},
                        }
                    }
                },
            }))
            old = config.HARDWARE_STORAGE_HANDOFF
            config.HARDWARE_STORAGE_HANDOFF = path
            try:
                result = hardware._collect_storage()
            finally:
                config.HARDWARE_STORAGE_HANDOFF = old
        self.assertEqual(result["status"], "ok")
        self.assertTrue(any("Test NVMe" in str(value) for _key, value in result["items"]))


class GpuTests(unittest.TestCase):
    def test_xml_metrics_and_thresholds(self):
        xml = """
        <nvidia_smi_log>
          <gpu id="0">
            <product_name>GPU</product_name>
            <temperature><gpu_temp>90 C</gpu_temp></temperature>
            <utilization><gpu_util>50 %</gpu_util></utilization>
            <fb_memory_usage><used>1 MiB</used><total>8 MiB</total></fb_memory_usage>
            <ecc_errors><volatile>
              <sram_uncorrectable>2</sram_uncorrectable>
              <dram_correctable>3</dram_correctable>
            </volatile></ecc_errors>
            <retired_pages><pending>1</pending></retired_pages>
            <clocks_throttle_reasons>
              <clocks_event_reason_hw_thermal_slowdown>Active</clocks_event_reason_hw_thermal_slowdown>
            </clocks_throttle_reasons>
          </gpu>
        </nvidia_smi_log>
        """
        gpus = hardware.parse_nvidia_xml(xml)
        self.assertEqual(len(gpus), 1)
        self.assertEqual(gpus[0]["ecc_uncorrected"], 2)
        self.assertEqual(gpus[0]["ecc_corrected"], 3)
        self.assertTrue(gpus[0]["throttle_active"])


class BmcTests(unittest.TestCase):
    def test_sel_lines_are_kept(self):
        lines = hardware.parse_ipmi_sel("1 | 01/01/2026 | Critical | PSU | Failure\n")
        self.assertEqual(len(lines), 1)


class SensorTests(unittest.TestCase):
    def test_sensor_threshold(self):
        values = hardware.parse_sensors_json({
            "chip": {"temp1_input": 95.0, "temp1_crit": 100.0}
        })
        self.assertEqual(values["chip/temp1_input"], 95.0)
        self.assertTrue(hardware.sensor_alerts(values))


class UncoreTests(unittest.TestCase):
    def test_events_are_filtered(self):
        text = """
        uncore_imc/data_reads/ [Kernel PMU event]
        uncore_imc/data_writes/ [Kernel PMU event]
        cpu/cycles/ [Hardware event]
        """
        self.assertEqual(
            hardware.parse_uncore_events(text),
            ["uncore_imc/data_reads/", "uncore_imc/data_writes/"],
        )

    def test_amd_pmu_events_are_uncore(self):
        text = """
        amd_iommu_0/cmd_processed/ [Kernel PMU event]
        amd_df_0/read_latency/ [Kernel PMU event]
        cpu/cycles/ [Hardware event]
        """
        self.assertEqual(
            hardware.parse_uncore_events(text),
            ["amd_iommu_0/cmd_processed/", "amd_df_0/read_latency/"],
        )


if __name__ == "__main__":
    unittest.main()
