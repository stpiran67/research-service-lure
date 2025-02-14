# Research Service Lure

---

## Introduction

This Python Script has been developed for use within my SANS MSISE Research report:

Validating the Effectiveness of MITRE Engage and Active Defense.

The research is structured to validate the hypothesis that an Active Defense deployment improves the overall security posture of an organization.

## ---

General Operation

The principle is that a deployed deception tool, this lure, can improve the detection of an insider threat as the threat actor prepares to move laterally, with the first link in the kill chain being service discovery (TA0007 \- Discovery).

This service lure creates a listening service and, when interacted with, will construct an API call to Cisco XDR to create a dynamic incident using the artifact of the threat and indications of compromise (IOCs) to create the unique incident.



