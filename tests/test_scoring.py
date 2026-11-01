"""V4 safety requirements and ordinal semantics, not empirical calibration."""
import math
import itertools
import pytest
from core.scoring import score_cve, calculate_hype, calculate_reality, exploit_ease, get_category

@pytest.mark.parametrize('signals,hype,reality,category',[
    ({},0,0,'Unknown'),
    ({'epss':0},0,0,'Quiet'),
    ({'in_kev':True},0,7,'Sleeper'),
    ({'wild_confirmation':True},0,7,'Sleeper'),
    ({'epss':0.9},0,4.5,'Watch'),
    ({'in_kev':True,'epss':0.01,'media_score':10,'tone_score':9,'branding':True},9.75,7,'Earned the hype'),
    ({'wild_confirmation':True,'epss':1,'public_poc':True},0,7,'Sleeper'),
    ({'in_kev':True,'ransomware_use':True,'epss':0.9},0,8,'Sleeper'),
    ({'epss':0.01,'media_score':10,'tone_score':9,'branding':True},9.75,0.05,'Overhyped'),
    ({'cvss':10,'poc_score':10,'epss':0},0,0,'Quiet'),
    ({'epss':0.9,'public_poc':True},0,5.5,'Watch'),
    ({'epss':0.00457,'poc_count':6},0,0.52,'Quiet'),
    ({'epss':0.00457,'poc_count':1},0,0.27,'Quiet'),
])
def test_safety_scenarios(signals,hype,reality,category):
    result=score_cve(signals)
    assert result == {'hype':hype,'reality':reality,'category':category}

@pytest.mark.parametrize('observed',['in_kev','wild_confirmation'])
def test_confirmation_dominates_all_prediction_and_attention_levels(observed):
    for epss,media,tone,brand in itertools.product((None,0,0.01,1),(0,5,10),(0,5,10),(False,True)):
        result=score_cve({observed:True,'epss':epss,'media_score':media,'tone_score':tone,'branding':brand})
        assert result['reality']>=7
        assert result['category'] in ('Sleeper','Earned the hype')

@pytest.mark.parametrize('value',[-100,-1,0,1,10,100,float('inf'),float('-inf'),float('nan'),None,'bad'])
def test_untrusted_numeric_values_never_escape_score_domain(value):
    scores=score_cve({key:value for key in ('cvss','epss','media_score','tone_score','poc_score','exploit_ease')})
    assert all(math.isfinite(scores[k]) and 0<=scores[k]<=10 for k in ('hype','reality'))

@pytest.mark.parametrize('vector,expected',[
    (None,0),('',0),('garbage',0),('CVSS:3.1/AV:N',0),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',10),
    ('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',4),
    ('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',5),
    ('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',6),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',7),
    ('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',4),
    ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',6),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L',10),
])
def test_versioned_vector_parser(vector,expected):
    assert exploit_ease(vector)==expected

def test_missing_prediction_cannot_be_labelled_overhyped():
    assert score_cve({'media_score':10,'tone_score':10,'branding':True})['category']=='Unknown'

def test_repository_popularity_and_cvss_do_not_manufacture_attention():
    assert calculate_hype({'cvss':10,'poc_score':10})==0

def test_ease_does_not_duplicate_epss_prediction():
    assert calculate_reality({'epss':0.4,'exploit_ease':10})==calculate_reality({'epss':0.4})

@pytest.mark.parametrize('hype,reality,expected',[(7,4.9,'Overhyped'),(6,7,'Earned the hype'),(5.99,7,'Sleeper'),(0,0,'Quiet')])
def test_category_boundaries(hype,reality,expected):
    assert get_category(hype,reality)==expected
