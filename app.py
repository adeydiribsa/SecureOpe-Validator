import streamlit as st
from scanner import scan_target, advanced_checks
from pdf_report import generate_pdf
from cis_checks import run_windows_checks, run_linux_checks, analyze_cis_output
import platform
from datetime import datetime
import os

st.set_page_config(page_title="Security Checker", layout="centered")

st.title("VFMFI Advanced Multi-Server Security Scanning Tool")

targets_input = st.text_area(
    "Enter targets (one per line)",
    "127.0.0.1\n192.168.1.1"
)

targets = [t.strip() for t in targets_input.split("\n") if t.strip()]

if st.button("Run Scan"):

    if not targets:
        st.error("Please enter targets")
    else:
        all_results = []
        all_issues = []

        with st.spinner("Running advanced scan..."):

            for target in targets:
                st.info(f"Scanning {target}")

                results = scan_target(target)

    # 🚨 HANDLE UNREACHABLE / ERROR
                if results.get("error"):
                    st.error(f"{target} → {results['error']}")

                    all_results.append({
                        "target": target,
                        "results": results,
                        "issues": [f"Scan failed: {results['error']}"]
                    })

                    all_issues.append(f"{target} unreachable")
                    continue  # ✅ MOVE TO NEXT SERVER

    # ✅ Continue normal scan
                net_issues = advanced_checks(results)

                system = platform.system()
                cis_output = run_windows_checks() if system == "Windows" else run_linux_checks()
                cis_issues = analyze_cis_output(cis_output)

                combined = net_issues + cis_issues

                all_results.append({
                    "target": target,
                    "results": results,
                    "issues": combined
                })

                all_issues.extend(combined)

        score = max(0, 100 - len(all_issues) * 3)
        st.metric("Security Score", f"{score}%")

        for host in all_results:
            st.subheader(host["target"])
            st.write("OS:", host["results"]["os"])
            st.write("Ports:", host["results"]["open_ports"])

            for issue in host["issues"]:
                st.warning(issue)

        # ✅ UNIQUE PDF FILE
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        generate_pdf(targets, all_results, all_issues, filename)

        # ✅ SAFE DOWNLOAD
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                st.download_button(
                    label="📄 Download Report",
                    data=f,
                    file_name=filename,
                    mime="application/pdf"
                )
        else:
            st.error("PDF generation failed")