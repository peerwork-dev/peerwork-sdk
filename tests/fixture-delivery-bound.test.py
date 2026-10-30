import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('bound',Path(__file__).with_name('fixture-delivery-bound.py'))
bound=importlib.util.module_from_spec(spec);spec.loader.exec_module(bound)

def sample(observed,pre):
    phases={group:{name:{'count':1,'monotonic':True,'elapsed_us':0}for name in names}
            for group,names in bound.PRE_SEND.items()}
    phases['send_execution']['body_prepare']['elapsed_us']=pre*1000
    phases['send_execution']['http_roundtrip']={'count':1,'monotonic':True,'elapsed_us':100000}
    return {'phases':phases,'receiver_observed_ms':observed}

class BoundTests(unittest.TestCase):
    def test_paired_bounds_are_not_subtracted_quantiles(self):
        rows=[sample(100,10),sample(200,100),sample(300,10)]
        stats=bound.distribution([bound.sample_bound(s,50)for s in rows])
        self.assertEqual(stats['p95_ms'],240)
        self.assertNotEqual(stats['p95_ms'],300-100-50)

    def test_repeated_reset_and_unfinished_phases_cannot_qualify(self):
        for field,value in [('count',2),('count',None),('monotonic',False),('elapsed_us',None)]:
            row=sample(200,10);row['phases']['send_execution']['body_prepare'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):bound.sample_bound(row,50)

    def test_invalid_ordering_is_rejected_instead_of_clamped(self):
        with self.assertRaises(ValueError):bound.sample_bound(sample(30,10),50)
        row=sample(200,10);row['phases']['send_execution']['http_roundtrip']['count']=2
        with self.assertRaises(ValueError):bound.sample_bound(row,50)

if __name__=='__main__':unittest.main()
