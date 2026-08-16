import copy, json, tempfile, unittest
from pathlib import Path
from agb_gate2b.neutral import load_corpus, validate_corpus
from generate_gate2b_neutral import trajectory
import random

class NeutralProtocolTests(unittest.TestCase):
    def items(self):
        definitions=[("calibration","A0","T0","F0"),("validation","A0","T2","F0"),("test-composition","A1","T2","F0"),("test-hidden-family","A0","T0","F2")]
        return [trajectory(i+1,split,4,bool(i%2),agent,tool,family,random.Random(i)) for i,(split,agent,tool,family) in enumerate(definitions)]
    def test_valid_protocol_has_hidden_family_and_no_leakage(self): self.assertFalse(validate_corpus(self.items())["leakage"])
    def test_structural_cross_split_leakage_is_rejected(self):
        items=self.items(); leaked=copy.deepcopy(items[0]); leaked["trajectory_id"]="ntraj:999999"; leaked["split"]="validation"; items.append(leaked)
        with self.assertRaisesRegex(ValueError,"leakage"): validate_corpus(items)
    def test_label_is_not_encoded_as_terminal_token(self):
        benign=trajectory(10,"calibration",4,False,"A0","T0","F0",random.Random(1)); malicious=trajectory(10,"calibration",4,True,"A0","T0","F0",random.Random(1))
        self.assertEqual(benign["tokens"][-1],1); self.assertEqual(malicious["tokens"][-1],1)
        self.assertNotIn(benign["label"], json.dumps(benign["events"]))
