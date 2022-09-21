# ChipsecExperimental

This repository is used by CHIPSEC as a staging/evaluation location for new features that are not yet ready for inclusion in CHIPSEC.

## Introduction

This repository is where new or experimental features that, are not ready for or may never make it to product 
integration, can be checked in for evaluation by the CHIPSEC community prior to introducing it into the CHIPSEC main trunk.  This serves several purposes:

* Encourage source code to be shared earlier in the development process.
* Allow source code to be shared that does not yet meet all CHIPSEC required quality criteria.
* Allow source code to be shared so the CHIPSEC community can help finish and validate new features.
* Provide a location to hold new features until they are deemed ready for integration.
* Provide a location to hold new features until there is a natural point in the CHIPSEC release cycle to fully validate the new feature.

Notes:

* Not intended to be used for bug fixes.
* Not intended to be used for small, simple, or low risk features.
* Creation of a branch does not guarantee feature integration into CHIPSEC. 

## Process for creating, using, and maintaining experimental efforts

1) ChipsecExperimental discussions can use:
	1) The existing chipsec mailing list for design/patch/test.
	1) The Discussion board on [chipsec/chipsec/discussions](https://github.com/chipsec/chipsec/discussions).
	
		Use the following style for discussion of a specific feature branch in ChipsecExperimental repo:
    
		`[ChipsecExperimental/branch]: Subject`

1) Process to add a new feature to ChipsecExperimental:
	1) Developer creates feature branch in ChipsecExperimental with `README.md` in root of feature branch with: summary, instructions to run, owners, timeline, and links to related materials.
	1) Developer is responsible for making sure feature is frequently synced to chipsec/main where possible.


1) Process to update sources in feature branch:
	1) Directly commit changes to feature branch.
	1) If community review is desired, send an email to the chipsec mailing list<email>: `[ChipsecExperimental/branch PATCH]: Subject`

1) Process to promote a ChipsecExperimental branch to CHIPSEC trunk:
	1) Integrate changes into chipsec fork or branch that is based on chipsec/main.
	1) Create standard pull request referencing ChipsecExperimental Branch.
	1) Update ChipsecExperimental Branch's `README.md` and on the first line place: ```# Archived: chipsec/chipsec/pull/[PR#]```
  
```
CHIPSEC Maintiners and Admins reserve the right to clean up/remove stale or unwanted branches at any time.
```
