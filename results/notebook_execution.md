# Notebook reproduction

All code cells of the depersonalized development notebook were executed with
scikit-learn 1.8.0. Plot displays used a non-interactive backend. The full run
completed in approximately 388 seconds in the build environment.

The original parameter searches reproduced these selections:

| Model | Selected setting |
| --- | --- |
| Logistic regression | C = 0.07163636363636361; comparison uses rounded C = 0.072 |
| KNN | 1 neighbour |
| Decision tree | Maximum depth 24; fitted comparison tree depth 22 |
| Random forest | 250 estimators; maximum depth 22 |

The selected full forest reproduced legitimate-class F1 of 0.9730013106159895.
It was saved before PCA training replaced the RF variable. The final PCA forest
has two inputs and is not the saved website classifier.

The KNN reproduction yielded legitimate-class F1 of 0.9586387434554974, compared
with 0.9608409986859395 stored in the supplied notebook. The selected neighbour
count remained 1. The exact cause of this small difference was not established;
the original package versions were not recorded in the source notebook.

`metrics.json` contains current held-out results for the selected full-feature
models and the separate eight-feature demo model. These are evaluations on the
precomputed website dataset, not raw-email or raw-URL validation. The notebook
retains clear output cells so users can generate their own results by rerunning it.
