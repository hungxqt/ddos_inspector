| Task ID |                   Task                   |   An  |  Phat |  Hung |  Hieu |  Dat |
| ------- | ---------------------------------------- | ----- | ----- | ----- | ----- | ---- |
|   0.1   |  Kick-off meeting & RACI alignment       |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.2   |  GitHub repo skeleton creation           |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.3   |  CI/CD pipeline setup                    |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.4   |  Environment provisioning (VMs & tools)  |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.5   |  Environment validation & report         |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.6   |  Access & permissions configuration      |  A/R  |   C   |   C   |   C   |   C  |(DONE)
|   0.7   |  Phase 0 wrap-up & sign-off              |  I    |  A/R  |   I   |   I   |   I  |(DONE)




| Task ID |      Sub-Phase        |   Start Date   |   End Date   |                   Deliverable                        |   Person in Charge   |
| ------- | --------------------- | -------------- | ------------ | ---------------------------------------------------- | -------------------- |
|   1.1   | Literature Review     | 08/05/2025     | 12/05/2025   | Comprehensive review of Snort, SnortML, DDoS attacks | Whole team           |(DONE)
|   1.2   | Technical Analysis    | 12/05/2025     | 15/05/2025   | Analysis of Snort rules, SnortML architecture        | Dat, Hieu            |(DONE)
|   1.3   | Gap Identification    | 15/05/2025     | 15/05/2025   | Identification of weaknesses in existing methods     | An, Hung             |(DONE)
|   1.4   | Research Drafting     | 16/05/2025     | 16/05/2025   | Draft of findings and technical notes                | Phat, Dat, Hieu      |
|   1.5   | Initial Documentation | 17/05/2025     | 17/05/2025   | Organized documentation for next phases              | Phat, An             |




| Task ID |                            Sub-Phase                        |   Start Date   |   End Date   |     Person in Charge     |
| ------- | ----------------------------------------------------------- | -------------- | ------------ | ------------------------ |
|   2.1   | Define plugin interface hooks (Snort 3 modular API)         | 17/05/2025     | 19/05/2025   | An, Hung (Phat, Dat <C>) |
|   2.2   | Design pre-filtering logic (exclude non-TCP/UDP traffic)    | 19/05/2025     | 21/05/2025   | An, Hung (Phat, Dat <C>) |
|   2.3   | Specify EWMA, entropy, and behavior detection modules       | 21/05/2025     | 22/05/2025   | An, Hung, Phat (Dat <C>) |
|   2.4   | Design shared data pipeline (Boost SPSC queue, metrics)     | 22/05/2025     | 23/05/2025   | An, Hung (Dat <C>)       |
|   2.5   | Finalize mitigation logic + rollback & auto-unban design    | 23/05/2025     | 25/05/2025   | An, Hung (Dat <C>)       |




|       CODE        |                    ROLE                                   |
| ----------------- | --------------------------------------------------------- |
|  Responsible (R)  |         The person(s) who actually do the work            |
|  Accountable (A)  |     The person who owns the outcome and must sign off     |
|   Consulted (C)   |  Those whose opinions are sought (two-way communication)  |
|    Informed (I)   |   Those who are kept up-to-date (one-way communication)   |
