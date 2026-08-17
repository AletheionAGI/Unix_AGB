import copy, json, tempfile, unittest
from pathlib import Path
from agb_gate2b.neutral import load_corpus, validate_corpus
from agb_gate2b.diagnostics import add_explicit_equality, balanced_items, canonicalize_entity_ids, confusion, counterfactual_pairs, distribution, permute_entity_ids, strip_distractors
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
    def test_diagnostic_subset_is_balanced_and_distractors_are_removed(self):
        candidates=[trajectory(i,"calibration",4,bool(i%2),"A0","T0","F0",random.Random(i)) for i in range(1,9)]
        subset=balanced_items(candidates,4)
        self.assertEqual([x["label"] for x in subset].count("benign"),2)
        reduced=strip_distractors(subset[0])
        self.assertEqual(len(reduced["events"]),6); self.assertEqual(len(reduced["tokens"]),25)
    def test_diagnostic_metric_summaries(self):
        self.assertEqual(confusion([False,True,False,True],[False,False,True,True]),{"tn":1,"fp":1,"fn":1,"tp":1})
        self.assertEqual(distribution([1.0,2.0,3.0,4.0])["p95"],4.0)
    def test_relational_probes_preserve_labels_and_transform_only_inputs(self):
        pair=[trajectory(10,"calibration",4,label,"A0","T0","F0",random.Random(7)) for label in (False,True)]
        permuted=permute_entity_ids(pair,9); explicit=add_explicit_equality(pair)
        self.assertEqual([x["label"] for x in permuted],[x["label"] for x in pair])
        self.assertNotEqual(permuted[0]["tokens"],pair[0]["tokens"])
        self.assertEqual(explicit[0]["tokens"][-2],16)
        self.assertEqual(explicit[1]["tokens"][-2],15)
        self.assertEqual(explicit[0]["tokens"][-1],explicit[1]["tokens"][-1])
    def test_canonical_ids_are_permutation_invariant_and_pairs_are_exact(self):
        pair=[trajectory(10,"calibration",4,label,"A0","T0","F0",random.Random(7)) for label in (False,True)]
        pair[0]["trajectory_id"]="probe:0:0"; pair[1]["trajectory_id"]="probe:0:1"
        canonical=canonicalize_entity_ids(pair)
        permuted_then_canonical=canonicalize_entity_ids(permute_entity_ids(pair,11))
        self.assertEqual([x["tokens"] for x in canonical],[x["tokens"] for x in permuted_then_canonical])
        self.assertEqual(len(counterfactual_pairs(pair)),1)
    def test_canonicalization_is_label_independent(self):
        item=trajectory(12,"calibration",1024,False,"A0","T0","F0",random.Random(5))
        relabeled=copy.deepcopy(item); relabeled["label"]="malicious"
        self.assertEqual(canonicalize_entity_ids([item])[0]["tokens"],canonicalize_entity_ids([relabeled])[0]["tokens"])
