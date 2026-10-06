# Dataset attribution

Mohammad, R. & McCluskey, L. (2012). *Phishing Websites* [Dataset].
UCI Machine Learning Repository. https://doi.org/10.24432/C51W2X

Dataset page: https://archive.ics.uci.edu/dataset/327/phishing

License: Creative Commons Attribution 4.0 International (CC BY 4.0).
https://creativecommons.org/licenses/by/4.0/

The supplied CSV contains 11,055 observations, 30 precomputed website features,
and the target column `Result`. It is redistributed unchanged as
`data/phishing_websites.csv`; the original notebook states it was converted from
ARFF to CSV. The original URLs and collection times are not included.

Labels: `-1` means phishing; `1` means legitimate. Feature values are encoded
separately, according to each rule. Zero is a defined category for certain
features, not a general missing-value indicator.

The supplied feature-definition document by Rami M. Mohammad, Fadi Thabtah,
and Lee McCluskey informed `FEATURES.md`. That document and the personal
presentation are not redistributed. The feature explanations here are summaries
with the implementation's assumptions explicitly recorded. The UCI page lists
this feature document among the dataset files.

The historical dataset is not a set of labeled emails. The accompanying model
weights and measured results are derived from this dataset. No author endorsement
of the demo or its email-link adaptation is implied.
