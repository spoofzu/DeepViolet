package com.mps.deepviolet.api;

import java.util.List;

class JsonLdrConfiguration {

	private String openssl_ciphersuites;
	private List<String> ciphersuites;
	private List<TLSVersion> tls_versions;
	private List<String> tls_curves;
	private List<String> certificate_types;
	private List<String> certificate_curves;
	private List<String> certificate_signatures;
	private int rsa_key_size;
	private String dh_param_size;
	private int ecdh_param_size;

	public int getRsa_key_size() {
		return rsa_key_size;
	}

	public void setRsa_key_size(int rsa_key_size) {
		this.rsa_key_size = rsa_key_size;
	}

	public String getDh_param_size() {
		return dh_param_size;
	}

	public void setDh_param_size(String dh_param_size) {
		this.dh_param_size = dh_param_size;
	}

	public int getEcdh_param_size() {
		return ecdh_param_size;
	}

	public void setEcdh_param_size(int ecdh_param_size) {
		this.ecdh_param_size = ecdh_param_size;
	}

	public int getHsts_min_age() {
		return hsts_min_age;
	}

	public void setHsts_min_age(int hsts_min_age) {
		this.hsts_min_age = hsts_min_age;
	}

	public List<String> getOldest_clients() {
		return oldest_clients;
	}

	public void setOldest_clients(List<String> oldest_clients) {
		this.oldest_clients = oldest_clients;
	}

	private int hsts_min_age;
	private List<String> oldest_clients;

	public String getOpenssl_ciphersuites() {
		return openssl_ciphersuites;
	}

	public void setOpenssl_ciphersuites(String openssl_ciphersuites) {
		this.openssl_ciphersuites = openssl_ciphersuites;
	}

	public List<String> getCiphersuites() {
		return ciphersuites;
	}

	public void setCiphersuites(List<String> ciphersuites) {
		this.ciphersuites = ciphersuites;
	}

	public List<TLSVersion> getTls_versions() {
		return tls_versions;
	}

	public void setTls_versions(List<TLSVersion> tls_versions) {
		this.tls_versions = tls_versions;
	}

	public List<String> getTls_curves() {
		return tls_curves;
	}

	public void setTls_curves(List<String> tls_curves) {
		this.tls_curves = tls_curves;
	}

	public List<String> getCertificate_types() {
		return certificate_types;
	}

	public void setCertificate_types(List<String> certificate_types) {
		this.certificate_types = certificate_types;
	}

	public List<String> getCertificate_signatures() {
		return certificate_signatures;
	}

	public void setCertificate_signatures(List<String> certificate_signatures) {
		this.certificate_signatures = certificate_signatures;
	}

	public List<String> getCertificate_curves() {
		return certificate_curves;
	}

	public void setCertificate_curves(List<String> certificate_curves) {
		this.certificate_curves = certificate_curves;
	}
}
