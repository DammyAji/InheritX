use super::types::{GeneticMarker, HealthMarker, PrivacyLevel, ProcessedDNAData};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    GeneticData,
    HealthRecord,
    BiometricData,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    Research,
    MedicalTreatment,
    GeneticCounseling,
    InsuranceUnderwriting,
    EmploymentScreening,
    Other,
}

impl ConsentPurpose {
    pub fn requires_explicit_genetic_consent(&self) -> bool {
        matches!(
            self,
            ConsentPurpose::InsuranceUnderwriting
                | ConsentPurpose::EmploymentScreening
                | ConsentPurpose::Other
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub user_id: u64,
    pub data_category: DataCategory,
    pub purpose: ConsentPurpose,
    pub granted: bool,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditEntry {
    pub timestamp: u64,
    pub user_id: u64,
    pub action: String,
    pub data_category: DataCategory,
    pub purpose: ConsentPurpose,
    pub law: ComplianceLaw,
    pub outcome: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceLaw {
    Hipaa,
    Gdpr,
    Gina,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceValidationResult {
    pub valid: bool,
    pub laws: Vec<ComplianceLaw>,
    pub violations: Vec<String>,
    pub details: serde_json::Value,
}

impl ComplianceValidationResult {
    fn new(laws: Vec<ComplianceLaw>, violations: Vec<String>, details: serde_json::Value) -> Self {
        Self {
            valid: violations.is_empty(),
            laws,
            violations,
            details,
        }
    }
}

pub struct GeneticPrivacyComplianceEngine {
    consents: HashMap<(u64, DataCategory, ConsentPurpose), ConsentRecord>,
    audit_log: Vec<ComplianceAuditEntry>,
    cross_border_transfers_allowed: bool,
}

impl GeneticPrivacyComplianceEngine {
    pub fn new() -> Self {
        Self {
            consents: HashMap::new(),
            audit_log: Vec::new(),
            cross_border_transfers_allowed: false,
        }
    }

    pub fn allow_cross_border_transfers(&mut self, allowed: bool) {
        self.cross_border_transfers_allowed = allowed;
    }

    pub fn grant_consent(
        &mut self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        jurisdiction: Option<String>,
        expires_at: Option<u64>,
    ) {
        let record = ConsentRecord {
            user_id,
            data_category,
            purpose,
            granted: true,
            granted_at: current_timestamp_secs(),
            expires_at,
            jurisdiction: jurisdiction.clone(),
        };

        self.consents
            .insert((user_id, data_category, purpose), record.clone());

        self.log_audit(
            user_id,
            "grant_consent".into(),
            data_category,
            purpose,
            ComplianceLaw::Gdpr,
            "granted".into(),
            json!({
                "jurisdiction": jurisdiction,
                "expires_at": expires_at,
            }),
        );
    }

    pub fn revoke_consent(
        &mut self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
    ) {
        if let Some(record) = self
            .consents
            .get_mut(&(user_id, data_category, purpose))
        {
            record.granted = false;
        }

        self.log_audit(
            user_id,
            "revoke_consent".into(),
            data_category,
            purpose,
            ComplianceLaw::Gdpr,
            "revoked".into(),
            json!({}),
        );
    }

    pub fn verify_consent(
        &self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        jurisdiction: Option<&str>,
    ) -> bool {
        let consent = self
            .consents
            .get(&(user_id, data_category, purpose));

        match consent {
            Some(record) if record.granted => {
                if let Some(expires_at) = record.expires_at {
                    if expires_at < current_timestamp_secs() {
                        return false;
                    }
                }

                if let Some(required_jurisdiction) = record.jurisdiction.as_deref() {
                    if let Some(current_jurisdiction) = jurisdiction {
                        return required_jurisdiction == current_jurisdiction;
                    }
                }

                true
            }
            _ => false,
        }
    }

    pub fn delete_user_consent_history(&mut self, user_id: u64) -> usize {
        let count = self
            .consents
            .keys()
            .filter(|(uid, _, _)| *uid == user_id)
            .count();

        self.consents
            .retain(|(uid, _, _), _| *uid != user_id);

        self.log_audit(
            user_id,
            "delete_user_data".into(),
            DataCategory::Other,
            ConsentPurpose::Other,
            ComplianceLaw::Gdpr,
            "deleted".into(),
            json!({ "deleted_consent_count": count }),
        );

        count
    }

    pub fn validate_hipaa_compliance(
        &mut self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        requested_data_fields: usize,
        purpose_is_medical: bool,
    ) -> ComplianceValidationResult {
        let mut violations = Vec::new();

        if !self.verify_consent(user_id, data_category, purpose, None) {
            violations.push("Informed consent is required under HIPAA".into());
        }

        if requested_data_fields > 20 {
            violations.push("Data minimization under HIPAA is violated: too many data fields requested".into());
        }

        if !purpose_is_medical {
            violations.push("HIPAA requires medical necessity and purpose limitation".into());
        }

        if data_category == DataCategory::GeneticData
            && purpose == ConsentPurpose::EmploymentScreening
        {
            violations.push("HIPAA does not permit genetic employment screening without express genetic privacy protection".into());
        }

        let result = ComplianceValidationResult::new(
            vec![ComplianceLaw::Hipaa],
            violations,
            json!({
                "requested_data_fields": requested_data_fields,
                "purpose_is_medical": purpose_is_medical,
            }),
        );

        self.log_audit(
            user_id,
            "validate_hipaa_compliance".into(),
            data_category,
            purpose,
            ComplianceLaw::Hipaa,
            if result.valid { "compliant".into() } else { "non_compliant".into() },
            result.details.clone(),
        );

        result
    }

    pub fn validate_gdpr_compliance(
        &mut self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        jurisdiction: Option<&str>,
        is_cross_border_transfer: bool,
        requested_data_fields: usize,
        user_requested_deletion: bool,
    ) -> ComplianceValidationResult {
        let mut violations = Vec::new();

        if !self.verify_consent(user_id, data_category, purpose, jurisdiction) {
            violations.push("GDPR requires explicit, informed consent for processing".into());
        }

        if requested_data_fields > 15 {
            violations.push("GDPR data minimization requirement violated".into());
        }

        if purpose == ConsentPurpose::Other && !self.verify_consent(user_id, data_category, purpose, jurisdiction) {
            violations.push("GDPR purpose limitation is violated for unspecified purpose".into());
        }

        if is_cross_border_transfer && !self.cross_border_transfers_allowed {
            violations.push("Cross-border transfer protections are missing under GDPR".into());
        }

        let result = ComplianceValidationResult::new(
            vec![ComplianceLaw::Gdpr],
            violations,
            json!({
                "jurisdiction": jurisdiction,
                "cross_border": is_cross_border_transfer,
                "requested_data_fields": requested_data_fields,
                "user_requested_deletion": user_requested_deletion,
            }),
        );

        if user_requested_deletion {
            let deleted_count = self.delete_user_consent_history(user_id);
            self.log_audit(
                user_id,
                "process_right_to_deletion".into(),
                data_category,
                purpose,
                ComplianceLaw::Gdpr,
                "deleted".into(),
                json!({ "deleted_consent_count": deleted_count }),
            );
        }

        self.log_audit(
            user_id,
            "validate_gdpr_compliance".into(),
            data_category,
            purpose,
            ComplianceLaw::Gdpr,
            if result.valid { "compliant".into() } else { "non_compliant".into() },
            result.details.clone(),
        );

        result
    }

    pub fn validate_genetic_privacy_compliance(
        &mut self,
        user_id: u64,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        requested_by: &str,
    ) -> ComplianceValidationResult {
        let mut violations = Vec::new();

        if !self.verify_consent(user_id, data_category, purpose, None) {
            violations.push("Explicit consent is required for genetic data processing".into());
        }

        if data_category == DataCategory::GeneticData
            && matches!(purpose, ConsentPurpose::InsuranceUnderwriting | ConsentPurpose::EmploymentScreening)
        {
            violations.push("GINA prohibits use of genetic data for employment or insurance underwriting".into());
        }

        if requested_by.is_empty() {
            violations.push("Genetic privacy compliance requires an identified data requester".into());
        }

        let result = ComplianceValidationResult::new(
            vec![ComplianceLaw::Gina],
            violations,
            json!({
                "requested_by": requested_by,
                "purpose": format!("{:?}", purpose),
            }),
        );

        self.log_audit(
            user_id,
            "validate_genetic_privacy_compliance".into(),
            data_category,
            purpose,
            ComplianceLaw::Gina,
            if result.valid { "compliant".into() } else { "non_compliant".into() },
            result.details.clone(),
        );

        result
    }

    pub fn anonymize_processed_data(
        &self,
        data: &ProcessedDNAData,
    ) -> ProcessedDNAData {
        let profile_id = self.hash_text(&data.profile_id);
        let genetic_markers = data
            .genetic_markers
            .iter()
            .map(|(id, marker)| {
                let value = match data.privacy_level {
                    PrivacyLevel::Public => marker.value.clone(),
                    PrivacyLevel::Protected => {
                        if Self::is_health_marker(id) {
                            self.hash_text(&marker.value)
                        } else {
                            marker.value.clone()
                        }
                    }
                    PrivacyLevel::Private | PrivacyLevel::Medical => self.hash_text(&marker.value),
                };

                (
                    id.clone(),
                    GeneticMarker {
                        marker_id: marker.marker_id.clone(),
                        marker_type: marker.marker_type.clone(),
                        value,
                    },
                )
            })
            .collect();

        let snp_data = data
            .snp_data
            .iter()
            .map(|record| {
                let mut record = record.clone();
                if !matches!(data.privacy_level, PrivacyLevel::Public) {
                    record.genotype = self.hash_text(&record.genotype);
                }
                record
            })
            .collect();

        let health_markers = if matches!(data.privacy_level, PrivacyLevel::Protected | PrivacyLevel::Private | PrivacyLevel::Medical) {
            data.health_markers
                .iter()
                .map(|marker| HealthMarker {
                    rsid: marker.rsid.clone(),
                    condition: marker.condition.clone(),
                    risk_allele: self.hash_text(&marker.risk_allele),
                    carrier_status: false,
                })
                .collect()
        } else {
            data.health_markers.clone()
        };

        ProcessedDNAData {
            profile_id,
            genetic_markers,
            snp_data,
            ancestry_composition: data.ancestry_composition.clone(),
            health_markers,
            privacy_level: data.privacy_level,
        }
    }

    pub fn pseudonymize_processed_data(&self, data: &ProcessedDNAData) -> ProcessedDNAData {
        let mut pseudonymized = self.anonymize_processed_data(data);
        pseudonymized.profile_id = self.hash_text(&pseudonymized.profile_id);
        pseudonymized
    }

    pub fn audit_log(&self) -> &[ComplianceAuditEntry] {
        &self.audit_log
    }

    fn log_audit(
        &mut self,
        user_id: u64,
        action: String,
        data_category: DataCategory,
        purpose: ConsentPurpose,
        law: ComplianceLaw,
        outcome: String,
        details: serde_json::Value,
    ) {
        self.audit_log.push(ComplianceAuditEntry {
            timestamp: current_timestamp_secs(),
            user_id,
            action,
            data_category,
            purpose,
            law,
            outcome,
            details,
        });
    }

    fn hash_text(&self, value: &str) -> String {
        let hash = digest(&SHA256, value.as_bytes());
        hex::encode(hash.as_ref())
    }

    fn is_health_marker(marker_id: &str) -> bool {
        matches!(
            marker_id,
            "rs429358"
                | "rs7412"
                | "rs1801133"
                | "rs6025"
                | "rs1799963"
                | "rs7903146"
                | "rs1333049"
        )
    }
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genetic_analysis::types::{AncestryBreakdown, GeneticMarker, HealthMarker, ProcessedDNAData, PrivacyLevel, SNPVariant, VariantSignificance};
    use std::collections::HashMap;

    fn sample_processed_data() -> ProcessedDNAData {
        let mut markers = HashMap::new();
        markers.insert(
            "rs429358".into(),
            GeneticMarker {
                marker_id: "rs429358".into(),
                marker_type: "health".into(),
                value: "CT".into(),
            },
        );
        markers.insert(
            "rs123456".into(),
            GeneticMarker {
                marker_id: "rs123456".into(),
                marker_type: "identity".into(),
                value: "AG".into(),
            },
        );

        ProcessedDNAData {
            profile_id: "test-profile".into(),
            genetic_markers: markers,
            snp_data: vec![SNPVariant {
                rsid: "rs429358".into(),
                chromosome: 19,
                position: 44908684,
                genotype: "CT".into(),
                significance: VariantSignificance::Pathogenic,
            }],
            ancestry_composition: AncestryBreakdown::default(),
            health_markers: vec![HealthMarker {
                rsid: "rs429358".into(),
                condition: "Alzheimer".into(),
                risk_allele: "C".into(),
                carrier_status: true,
            }],
            privacy_level: PrivacyLevel::Protected,
        }
    }

    #[test]
    fn test_consent_management_grant_and_revoke() {
        let mut engine = GeneticPrivacyComplianceEngine::new();
        engine.grant_consent(
            1,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            Some("EU".into()),
            None,
        );

        assert!(engine.verify_consent(
            1,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            Some("EU"),
        ));

        engine.revoke_consent(1, DataCategory::GeneticData, ConsentPurpose::MedicalTreatment);
        assert!(!engine.verify_consent(
            1,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            Some("EU"),
        ));
    }

    #[test]
    fn test_hipaa_compliance_requires_informed_consent() {
        let mut engine = GeneticPrivacyComplianceEngine::new();
        let result = engine.validate_hipaa_compliance(
            2,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            2,
            true,
        );

        assert!(!result.valid);
        assert!(result
            .violations
            .iter()
            .any(|v| v.contains("Informed consent")));
    }

    #[test]
    fn test_gdpr_cross_border_restriction() {
        let mut engine = GeneticPrivacyComplianceEngine::new();
        engine.grant_consent(
            3,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            Some("EU".into()),
            None,
        );

        let result = engine.validate_gdpr_compliance(
            3,
            DataCategory::GeneticData,
            ConsentPurpose::MedicalTreatment,
            Some("EU"),
            true,
            5,
            false,
        );

        assert!(!result.valid);
        assert!(result
            .violations
            .iter()
            .any(|v| v.contains("Cross-border transfer")));
    }

    #[test]
    fn test_gina_forbids_employment_screening() {
        let mut engine = GeneticPrivacyComplianceEngine::new();
        engine.grant_consent(
            4,
            DataCategory::GeneticData,
            ConsentPurpose::EmploymentScreening,
            Some("US".into()),
            None,
        );

        let result = engine.validate_genetic_privacy_compliance(
            4,
            DataCategory::GeneticData,
            ConsentPurpose::EmploymentScreening,
            "hr_portal",
        );

        assert!(!result.valid);
        assert!(result
            .violations
            .iter()
            .any(|v| v.contains("employment or insurance underwriting")));
    }

    #[test]
    fn test_anonymize_profile_pseudonymizes_sensitive_fields() {
        let engine = GeneticPrivacyComplianceEngine::new();
        let data = sample_processed_data();
        let anonymized = engine.anonymize_processed_data(&data);

        assert_ne!(anonymized.profile_id, data.profile_id);
        assert_eq!(anonymized.snp_data[0].rsid, data.snp_data[0].rsid);
        assert_ne!(anonymized.snp_data[0].genotype, data.snp_data[0].genotype);
        assert_eq!(anonymized.health_markers[0].condition, data.health_markers[0].condition);
        assert_ne!(anonymized.health_markers[0].risk_allele, data.health_markers[0].risk_allele);
    }

    #[test]
    fn test_audit_logging_records_compliance_actions() {
        let mut engine = GeneticPrivacyComplianceEngine::new();
        engine.grant_consent(
            5,
            DataCategory::GeneticData,
            ConsentPurpose::Research,
            Some("EU".into()),
            None,
        );
        engine.validate_gdpr_compliance(
            5,
            DataCategory::GeneticData,
            ConsentPurpose::Research,
            Some("EU"),
            false,
            1,
            false,
        );

        assert!(!engine.audit_log().is_empty());
        assert!(engine
            .audit_log()
            .iter()
            .any(|entry| entry.action == "grant_consent"));
        assert!(engine
            .audit_log()
            .iter()
            .any(|entry| entry.action == "validate_gdpr_compliance"));
    }
}
