/* ═══════════════════════════════════════════════════════════
   PAPER TEMPLATES
═══════════════════════════════════════════════════════════ */
const TMPLS = [
    {
        name: '학위논문 (사회과학·교육학·심리학)', icon: '🎓', desc: '국문초록, Abstract, 6장 구조', content: `# 논문 제목

---

## 국문초록

핵심어: 

---

## Abstract

Keywords: 

---

## 목차

---

## 표 목차

---

## 그림 목차

---

# 제1장 서론

## 1. 연구의 필요성

## 2. 연구 목적

## 3. 연구 문제

1. 
2. 

## 4. 연구 가설

## 5. 용어의 정의

## 6. 연구의 제한점

<div class="page-break"></div>

# 제2장 이론적 배경

## 1. 핵심 이론

## 2. 선행연구 고찰

## 3. 연구모형 설정

<div class="page-break"></div>

# 제3장 연구방법

## 1. 연구대상

## 2. 연구도구

## 3. 자료수집 절차

## 4. 분석방법

## 5. 연구모형 분석전략

<div class="page-break"></div>

# 제4장 연구결과

## 1. 기술통계

## 2. 측정모형 검증

## 3. 구조모형 분석

## 4. 추가 분석

<div class="page-break"></div>

# 제5장 논의

## 1. 결과 해석

## 2. 이론적 시사점

## 3. 실천적 시사점

<div class="page-break"></div>

# 제6장 결론

## 1. 연구 요약

## 2. 정책적 제언

## 3. 후속연구 제안

<div class="page-break"></div>

# 참고문헌

<div class="ref-block">

</div>

---

# 부록
`},
    {
        name: 'SSCI / KCI 학술지', icon: '📰', desc: '국제학술지 표준 IMRaD 구조', content: `# 논문 제목

**Authors:** 

**Journal:** 

**Received:** | **Accepted:** | **Published:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

## 1.1 Background

## 1.2 Research Gap

## 1.3 Research Purpose

<div class="page-break"></div>

# 2. Literature Review

<div class="page-break"></div>

# 3. Theoretical Framework and Hypotheses

**H1:** 

**H2:** 

<div class="page-break"></div>

# 4. Method

## 4.1 Participants

## 4.2 Measures

## 4.3 Procedure

## 4.4 Data Analysis

<div class="page-break"></div>

# 5. Results

<div class="page-break"></div>

# 6. Discussion

## 6.1 Theoretical Implications

## 6.2 Practical Implications

## 6.3 Limitations and Future Research

<div class="page-break"></div>

# 7. Conclusion

<div class="page-break"></div>

# References

<div class="ref-block">

</div>
`},
    {
        name: '단일 연구 논문 (실증)', icon: '🔬', desc: '서론-방법-결과-논의 4단 구조', content: `# 논문 제목

**저자:** 

---

## 요약

**주요어:** 

---

# 1. 서론

<div class="page-break"></div>

# 2. 이론적 배경 및 가설 설정

## 2.1 이론적 배경

## 2.2 연구 가설

**가설 1:** 

**가설 2:** 

<div class="page-break"></div>

# 3. 연구방법

## 3.1 연구대상

## 3.2 측정도구

## 3.3 분석방법

<div class="page-break"></div>

# 4. 연구결과

## 4.1 기술통계

## 4.2 가설 검증

<div class="page-break"></div>

# 5. 논의 및 결론

## 5.1 논의

## 5.2 결론

## 5.3 연구의 한계

# 참고문헌

<div class="ref-block">

</div>
`},
    {
        name: '다중 연구 (Study 1 / Study 2)', icon: '📊', desc: '복수 연구 포함 실증 논문 구조', content: `# 논문 제목

**Authors:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

<div class="page-break"></div>

# 2. Study 1

## 2.1 Method

### 2.1.1 Participants

### 2.1.2 Measures

### 2.1.3 Procedure

## 2.2 Results

## 2.3 Discussion

<div class="page-break"></div>

# 3. Study 2

## 3.1 Method

### 3.1.1 Participants

### 3.1.2 Measures

### 3.1.3 Procedure

## 3.2 Results

## 3.3 Discussion

<div class="page-break"></div>

# 4. General Discussion

## 4.1 Theoretical Contributions

## 4.2 Practical Implications

## 4.3 Limitations and Future Research

# References

<div class="ref-block">

</div>
`},
    {
        name: '메타분석 논문', icon: '📈', desc: '체계적 문헌 검토 및 메타분석', content: `# 논문 제목: A Meta-Analysis

**Authors:** 

---

## Abstract

**Keywords:** 

---

# 1. Introduction

## 1.1 Theoretical Background

## 1.2 Purpose of Meta-Analysis

<div class="page-break"></div>

# 2. Literature Search Strategy

## 2.1 Search Databases

## 2.2 Search Keywords

## 2.3 Search Period

<div class="page-break"></div>

# 3. Inclusion Criteria

## 3.1 Inclusion Criteria

## 3.2 Exclusion Criteria

## 3.3 PRISMA Flow Diagram

<div class="page-break"></div>

# 4. Coding Procedure

## 4.1 Variables Coded

## 4.2 Coder Agreement

<div class="page-break"></div>

# 5. Statistical Analysis

## 5.1 Effect Size Calculation

## 5.2 Heterogeneity Test

## 5.3 Moderator Analysis

<div class="page-break"></div>

# 6. Results

## 6.1 Overall Effect Size

## 6.2 Moderator Effects

<div class="page-break"></div>

# 7. Publication Bias Test

## 7.1 Funnel Plot

## 7.2 Egger's Test

<div class="page-break"></div>

# 8. Discussion

## 8.1 Interpretation of Effect Sizes

## 8.2 Practical Implications

## 8.3 Limitations

# References

<div class="ref-block">

</div>

---

# Appendix

## Appendix A: List of Included Studies
`},
];