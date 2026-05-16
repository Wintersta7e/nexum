//! The Embedder — owns the ORT session + tokenizer + the embedding-dim
//! constant. Cheap to clone; safe to share across threads (the session
//! lives behind `InferenceCell` which serializes callers on a mutex
//! because `Session::run` takes `&mut self` even though `Session: Send + Sync`).

use std::path::Path;
use std::sync::Arc;

use ndarray::{Array2, Axis};
use ort::session::Session;
use ort::value::TensorRef;
use tokenizers::{Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};

use super::inference_cell::InferenceCell;
use super::types::{EMBED_DIM, EmbedError};

/// Dense-embedding handle. Cheap to clone; safe to share across threads.
#[derive(Clone)]
pub struct Embedder {
    session: InferenceCell,
    tokenizer: Arc<Tokenizer>,
}

const MODEL_ONNX: &str = "model.onnx";
const TOKENIZER_JSON: &str = "tokenizer.json";

impl Embedder {
    /// Load bge-m3 from `model_dir`. Expects `model.onnx` (with sibling
    /// external-data files `model.onnx_data` + `Constant_7_attr__value`)
    /// and `tokenizer.json` in the same directory.
    ///
    /// # Errors
    /// `EmbedError::ModelNotInstalled` if `model.onnx` or `tokenizer.json`
    /// is absent. `EmbedError::OrtInit` on session-builder failure.
    /// `EmbedError::Tokenize` on tokenizer parse failure.
    pub fn load(model_dir: &Path) -> Result<Self, EmbedError> {
        let model_path = model_dir.join(MODEL_ONNX);
        if !model_path.exists() {
            return Err(EmbedError::ModelNotInstalled {
                reason: format!(
                    "model.onnx not found under {} — run `nexum models install bge-m3`",
                    model_dir.display()
                ),
            });
        }
        let tokenizer_path = model_dir.join(TOKENIZER_JSON);
        if !tokenizer_path.exists() {
            return Err(EmbedError::ModelNotInstalled {
                reason: format!(
                    "tokenizer.json not found under {} — run `nexum models install bge-m3`",
                    model_dir.display()
                ),
            });
        }

        let mut builder = Session::builder().map_err(EmbedError::ort_init)?;
        let session = builder
            .commit_from_file(&model_path)
            .map_err(EmbedError::ort_init)?;

        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| EmbedError::tokenize_from_message(e.to_string()))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: 8192,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
                direction: TruncationDirection::Right,
            }))
            .map_err(|e| EmbedError::tokenize_from_message(e.to_string()))?;

        Ok(Self {
            session: InferenceCell::new(session),
            tokenizer: Arc::new(tokenizer),
        })
    }

    /// Compute the dense embedding for one text. Returns a
    /// 1024-dim L2-normalized vector (normalization happens inside
    /// the ONNX graph; we don't redo it).
    ///
    /// # Errors
    /// `EmbedError::Tokenize` on tokenization failure.
    /// `EmbedError::OrtRun` on inference failure.
    /// `EmbedError::OutputShapeMismatch` if the graph returned an
    /// unexpected shape (defense in depth against a future export drift).
    pub fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| EmbedError::tokenize_from_message(e.to_string()))?;
        let ids: Vec<i64> = encoding.get_ids().iter().map(|&x| i64::from(x)).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&x| i64::from(x))
            .collect();
        let seq_len = ids.len();

        let input_ids = Array2::from_shape_vec((1, seq_len), ids).map_err(EmbedError::ort_run)?;
        let attention_mask =
            Array2::from_shape_vec((1, seq_len), mask).map_err(EmbedError::ort_run)?;

        self.session.run(|session| {
            let outputs = session
                .run(ort::inputs![
                    "input_ids" => TensorRef::from_array_view(&input_ids)
                        .map_err(EmbedError::ort_run)?,
                    "attention_mask" => TensorRef::from_array_view(&attention_mask)
                        .map_err(EmbedError::ort_run)?,
                ])
                .map_err(EmbedError::ort_run)?;

            let sentence = outputs["sentence_embedding"]
                .try_extract_array::<f32>()
                .map_err(EmbedError::ort_run)?;

            let shape: Vec<usize> = sentence.shape().to_vec();
            if shape.len() != 2 || shape[0] != 1 || shape[1] != EMBED_DIM {
                return Err(EmbedError::OutputShapeMismatch {
                    expected: vec![1, EMBED_DIM],
                    actual: shape,
                });
            }

            Ok(sentence.index_axis(Axis(0), 0).iter().copied().collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_dir_from_env() -> Option<std::path::PathBuf> {
        std::env::var_os("NEXUM_TEST_BGE_M3_DIR").map(std::path::PathBuf::from)
    }

    #[test]
    fn load_returns_model_not_installed_for_missing_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        match Embedder::load(temp.path()) {
            Err(EmbedError::ModelNotInstalled { .. }) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected ModelNotInstalled, got Ok"),
        }
    }

    #[test]
    #[ignore = "requires bge-m3 model on disk; set NEXUM_TEST_BGE_M3_DIR"]
    fn embed_returns_1024_dim_vector() {
        let Some(dir) = model_dir_from_env() else {
            return;
        };
        let embedder = Embedder::load(&dir).expect("model loads");
        let vec = embedder
            .embed("The quick brown fox jumps over the lazy dog.")
            .expect("inference");
        assert_eq!(vec.len(), 1024);
        assert!(vec.iter().all(|f| f.is_finite()));
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-3,
            "graph output should be L2-normalized; got norm = {norm}"
        );
    }

    #[test]
    #[ignore = "requires bge-m3 model on disk; set NEXUM_TEST_BGE_M3_DIR"]
    fn embed_is_deterministic_for_same_input() {
        let Some(dir) = model_dir_from_env() else {
            return;
        };
        let embedder = Embedder::load(&dir).expect("model loads");
        let a = embedder.embed("test input").expect("inference 1");
        let b = embedder.embed("test input").expect("inference 2");
        assert_eq!(
            a, b,
            "ORT inference must be deterministic on identical input"
        );
    }
}
