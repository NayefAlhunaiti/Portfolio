import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

stub_module = types.ModuleType("ml_pipeline.local_model")


def generate_text(prompt, config):
    return "stubbed fallback"


stub_module.generate_text = generate_text
sys.modules.setdefault("ml_pipeline", types.ModuleType("ml_pipeline"))
sys.modules["ml_pipeline.local_model"] = stub_module

import app


def test_config(llm_synthesis=False):
    config = app.load_config()
    config["llm_synthesis"] = llm_synthesis
    return config


class KnowledgeRoutingTests(unittest.TestCase):
    def test_requisition_approval_query_matches_local_knowledge(self):
        item = app.match_ariba_knowledge("How do I approve a requisition for a purchase?", "Need a review before release")
        self.assertIsNotNone(item)
        self.assertIn("approval", (item.get("id") or "").lower())

    def test_tcode_lookup_uses_local_sap_catalog(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "What is ME51N?", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertIn("ME51N", answer)
        self.assertIn("Create Purchase Requisition", answer)
        self.assertNotIn("ME52N", answer)

    def test_paraphrased_po_display_request_maps_to_display_tcode(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "Can you show me the PO number details?", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "me23n")
        self.assertEqual(item.get("functionality_id"), "procurement_mm")
        self.assertIn("ME23N", answer)
        self.assertIn("Procurement", answer)
        self.assertNotIn("ME21N", answer)

    def test_generic_tcode_request_returns_compact_guidance_not_full_catalog(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "what are t codes?", "context": ""},
            test_config(),
            [],
        )
        self.assertEqual(item.get("id"), "sap_shortcut_catalog")
        self.assertIn("SAP T-code guidance", answer)
        self.assertIn("ME51N", answer)
        self.assertNotIn("Warehouse Management", answer)
        self.assertNotIn("Financial Accounting", answer)

    def test_tcode_catalog_uses_llm_synthesis_when_enabled(self):
        llm_answer = "SAP T-codes are SAP GUI/S/4HANA transaction codes. For procurement, common examples include ME51N for purchase requisitions and ME23N for display purchase orders."
        with patch.object(app, "call_local_model", return_value=llm_answer) as mocked:
            answer, item = app.route_answer(
                {"role": "buyer", "message": "list t codes for procurement", "context": ""},
                test_config(llm_synthesis=True),
                [],
            )
        self.assertTrue(mocked.called)
        self.assertEqual(item.get("id"), "sap_shortcut_catalog")
        self.assertEqual(answer, llm_answer)

    def test_downloaded_ariba_knowledge_base_is_loaded(self):
        knowledge = app.load_knowledge_base()
        source_types = {item.get("source_type") for item in knowledge}
        self.assertIn("downloaded_ariba_kb", source_types)
        self.assertTrue(any(item.get("id") == "ariba_deep_dive_approval_delegation" for item in knowledge))

    def test_enterprise_hr_and_it_helpdesk_knowledge_is_loaded(self):
        knowledge = app.load_knowledge_base()
        source_types = {item.get("source_type") for item in knowledge}
        self.assertIn("enterprise_helpdesk", source_types)
        self.assertTrue(any(item.get("id") == "hr_0002" for item in knowledge))
        self.assertTrue(any(item.get("id") == "it_0001" for item in knowledge))

    def test_password_reset_routes_to_it_helpdesk_knowledge(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "I forgot my password and cannot sign in", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "it_0001")
        self.assertEqual(item.get("source_type"), "enterprise_helpdesk")
        self.assertIn("self-service password reset", answer)

    def test_annual_leave_routes_to_hr_knowledge(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "How do I request annual leave?", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "hr_0002")
        self.assertEqual(item.get("source_type"), "enterprise_helpdesk")
        self.assertIn("HR system", answer)

    def test_specific_approval_delegation_uses_downloaded_deep_dive(self):
        item = app.match_ariba_knowledge("What is approval delegation in Ariba?", "")
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "ariba_deep_dive_approval_delegation")
        self.assertEqual(item.get("source_type"), "downloaded_ariba_kb")

    def test_stuck_requisition_uses_downloaded_troubleshooting(self):
        item = app.match_ariba_knowledge("How do I fix a requisition stuck with no approver assigned?", "")
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "ariba_troubleshooting_1")
        self.assertEqual(item.get("source_type"), "downloaded_ariba_kb")

    def test_stuck_requisition_route_does_not_collide_with_change_tcode(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "How do I fix a requisition stuck with no approver assigned?", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "ariba_troubleshooting_1")
        self.assertNotIn("ME52N", answer)

    def test_requisition_approval_does_not_collide_with_create_requisition_tcode(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "approve requisition", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "requisition_approval")
        self.assertNotIn("ME51N", answer)

    def test_supplier_onboarding_does_not_collide_with_vendor_create_tcode(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "supplier onboarding", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.get("id"), "supplier_onboarding")
        self.assertNotIn("XK01", answer)

    def test_exact_tcode_related_sources_do_not_pull_ariba_workflow_noise(self):
        sources = app.find_relevant_sources("What is ME51N?", "", max_items=5)
        self.assertTrue(sources)
        self.assertTrue(all(source.get("source_type") in {"downloaded_tcode", "official_sap_doc"} for source in sources))

    def test_task_paraphrases_pick_each_action_specific_tcode(self):
        cases = [
            ("raise a purchase requisition", "me51n", "ME51N"),
            ("modify an existing supplier record", "xk02", "XK02"),
            ("pull up outbound delivery status", "vl03n", "VL03N"),
            ("compare supplier quotes", "me49", "ME49"),
            ("track background jobs", "sm37", "SM37"),
        ]
        for message, expected_id, expected_code in cases:
            with self.subTest(message=message):
                answer, item = app.route_answer(
                    {"role": "buyer", "message": message, "context": ""},
                    test_config(),
                    [],
                )
                self.assertIsNotNone(item)
                self.assertEqual(item.get("id"), expected_id)
                self.assertIn(expected_code, answer)

    def test_ariba_abbreviations_route_to_specific_knowledge(self):
        cases = [
            ("What is RFQ in Ariba sourcing?", "abbrev_rfq"),
            ("CIG HTTP 500 for cXML PO attachment", "master_integ_001"),
            ("What does SLP mean?", "abbrev_slp"),
            ("SES approval in procurement", "master_v4_3fe12f1f"),
            ("GR for PO", "abbrev_gr"),
            ("What does CRO mean?", "abbrev_cro"),
        ]
        for message, expected_id in cases:
            with self.subTest(message=message):
                answer, item = app.route_answer(
                    {"role": "buyer", "message": message, "context": ""},
                    test_config(),
                    [],
                )
                self.assertIsNotNone(item)
                self.assertEqual(item.get("id"), expected_id)
                self.assertNotIn("ME52N", answer)

    def test_procurement_abbreviations_still_allow_sap_tcode_tasks(self):
        cases = [
            ("display PO details", "me23n", "ME23N"),
            ("create PR", "me51n", "ME51N"),
        ]
        for message, expected_id, expected_code in cases:
            with self.subTest(message=message):
                answer, item = app.route_answer(
                    {"role": "buyer", "message": message, "context": ""},
                    test_config(),
                    [],
                )
                self.assertIsNotNone(item)
                self.assertEqual(item.get("id"), expected_id)
                self.assertIn(expected_code, answer)

    def test_request_payload_is_supported_without_message_key(self):
        answer, item = app.route_answer(
            {"role": "buyer", "request": "How do I register a buyer in Ariba?", "context": ""},
            test_config(),
            [],
        )
        self.assertIsNotNone(item)
        self.assertIn("Buyer", answer)
        self.assertIn("Ariba", answer)

    def test_greeting_does_not_call_model_or_fake_workflow(self):
        answer, item = app.route_answer(
            {"role": "buyer", "message": "hello", "context": ""},
            test_config(),
            [],
        )
        self.assertEqual(item.get("id"), "greeting")
        self.assertIn("SAP Ariba", answer)

    def test_human_answers_use_llm_synthesis_when_enabled(self):
        llm_answer = "ME51N is the SAP transaction for creating a purchase requisition. Use it when you need to start a PR, then follow your approval flow."
        with patch.object(app, "call_local_model", return_value=llm_answer) as mocked:
            answer, item = app.route_answer(
                {"role": "buyer", "message": "What is ME51N?", "context": ""},
                test_config(llm_synthesis=True),
                [],
            )
        self.assertTrue(mocked.called)
        self.assertIsNotNone(item)
        self.assertEqual(answer, llm_answer)


if __name__ == "__main__":
    unittest.main()
