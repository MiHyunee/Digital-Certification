## 4. Certificate and Certificate Extension Profile

이 섹션에서는 상호운용성과 재사용 가능한 PKI를 강화하는 공개 키 인증서에 대한 프로파일을 제공한다. 이 섹션은 X.509 v3 인증서 형식과 [X.509]에 정의된 표준 인증서 확장을 기반으로 한다.

ISO/IEC와 ITU-T 문서는 ASN.1의 1997년 버전을 사용하지만, 이 문서는 1988년 ASN.1 구문을 사용하며 인코딩된 인증서와 표준 확장은 동일하다. 또한 이 절에서는 인터넷 커뮤니티를 위한 PKI를 지원하는 데 필요한 개인 확장을 정의한다.

인증서는 광범위한 상호 운용성 목표와 광범위한 운영 및 보증 요구 사항을 다루는 광범위한 응용 프로그램 및 환경에서 사용될 수 있다. 이 문서의 목표는 광범위한 상호운용성과 제한된 특수 목적 요구사항을 요구하는 일반 애플리케이션에 대한 공통 기준선을 설정에 있다. 특히 비공식 인터넷 전자우편, IPsec, WWW 애플리케이션에 X.509 v3 인증서 사용을 지원하는 데 중점을 둘 예정이다.

### 4.1 Basic Certificate Fields

X.509 v3 인증서의 기본 구문은 다음과 같다. 서명 계산을 위해 서명할 데이터는 ASN.1 고유 인코딩 규칙(DER)을 사용하여 인코딩된다[X.690]. ASN.1 DER 인코딩은 각 요소에 대한 태그, 길이, 값 인코딩 시스템입니다.

```
Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
```

다음 항목에서는 인터넷에서 사용하기 위한 X.509 v3 인증서에 대해 설명한다.

#### 4.1.1 Certificate Fields
Certificate는 세 가지 필수 필드의 시퀀스이다. 

- tbsCertificate   
필드에는 주체 및 발행자의 이름, 주체와 관련된 공개 키, 유효 기간 및 기타 관련 정보 포함.

- signatureAlgorithm   
CA가 이 인증서에 서명하는 데 사용하는 암호화 알고리즘의 식별자가 포함. [PKIXALGS]는 지원되는 서명 알고리즘을 나열하지만 다른 서명 알고리즘도 지원 가능.

     알고리즘 식별자의 ASN.1 구조 정의
     ```
     AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
     ```

    Algorithm identifier는 암호화 알고리즘을 식별하기 위해 사용된다. OBJECT Identifier 구성 요소는 알고리즘(예: SHA-1이 있는 DSA)을 식별한다. Optional parameters 필드의 내용은 식별된 알고리즘에 따라 달라진다.

    이 필드는 tbsCertificate의 서명 필드와 동일한 알고리즘 식별자를 포함해야 한다.

- signatureValue   
ASN.1 DER 인코딩된 tbsCertificate에서 계산한 디지털 서명 포함. ASN.1 DER 인코딩된 tbsCertificate는 서명 함수의 입력으로 사용된다. 이 서명 값은 BIT STRING으로 인코딩되어 서명(signature) 필드에 포함된다. 이 프로세스의 세부사항은 [PKIXALGS]에 나열된 각 알고리즘에 대해 지정된다. 

    이 서명을 생성함으로써 CA는 tbsCertificate 필드에 있는 정보의 유효성을 인증한다. 특히 CA는 공개 키 자료와 인증서 주체 간의 바인딩을 인증한다.


#### 4.1.2 TBSCertificate

```
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING  }
```

TBSCertificate 시퀀스에는 인증서의 주체 및 인증서를 발급한 CA와 관련된 정보가 포함된다. 모든 TBSCertificate에는 주체 및 발급자의 이름, 주체와 관련된 공개 키, 유효 기간, 버전 번호 및 일련 번호가 포함되며, 선택적인 고유 식별자 필드를 포함할 수 있다. 이 절의 나머지 부분에서는 이러한 필드의 구문 및 의미를 설명한다. TBSCertificate는 일반적으로 Extension 을 포함한다. 인터넷 PKI를 위한 Extension은 섹션 4.2에 설명되어 있다.

4.1.2.1 Version   
인코딩된 인증서의 버전을 설명.      
- Version 3 : Extension이 사용되는 경우(값은 2).
- Version 2 이상: 확장자가 없지만 UniqueIdentifier가 있는 경우(값은 1)(이런 경우 version 2, 3 모두 가능)
- version 1 이상 : 기본 필드만 있는 경우 (기본값으로 인증서에서 값이 생략됨). (버전 2 또는 3일 수 있음)

모든 버전 인증서를 수락할 수 있도록 구현해야 한다. 최소한 적합한 구현체는 버전 3 인증서를 인식해야 한다.

이 프로필을 기반으로 하는 구현에서는 버전 2 인증서 생성이 불가하다.

4.1.2.2 Serial Number   
CA에서 각 인증서에 할당한 양의 정수. 주어진 CA에 의해 발행된 각 인증서에 대해 고유한 값이다(즉, 발행자 이름과 일련 번호는 고유한 인증서를 식별한다). CA는 serialNumber를 음수가 아닌 정수로 만들어야 한다.

위의 고유성 요구사항을 고려할 때 일련번호는 긴 정수를 포함할 것으로 예상할 수 있다. 인증서 사용자는 serial Number 값을 최대 20 옥텟까지 처리할 수 있어야 한다. CA는 20 옥텟보다 긴 serial Number 값을 사용하면 안 된다.

4.1.2.3 Signature   
CA가 인증서에 서명하는 데 사용하는 알고리즘에 대한 알고리즘 식별자 포함. 

이 필드는 반드시 시퀀스 인증서의 signatureAlgorithm 필드와 동일한 알고리즘 식별자를 포함해야 한다. 선택적 매개변수 필드(AlgorithmIdentifier.parameters)의 내용은 식별된 알고리즘에 따라 달라진다. [PKIXALGS]는 지원되는 서명 알고리즘을 나열하지만 다른 서명 알고리즘도 지원 가능하다.

4.1.2.4 Issuer   
인증서에 서명하고 발급한 엔티티를 식별. 비어 있지 않은 고유 이름(DN)을 포함해야 하며 [X.501]으로 정의된다.

```
Name ::= CHOICE { RDNSequence }

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue }

AttributeType ::= OBJECT IDENTIFIER

AttributeValue ::= ANY DEFINED BY AttributeType
```

Name은 국가 이름과 같은 속성과 해당 값(예: US)으로 구성된 계층적 이름이다. 구성 요소 AttributeValue의 유형은 AttributeType에 의해 결정되는데, 일반적으로 DirectoryString이다. 

DirectoryString 유형은 PrintableString, TeletexString, BMPSString, UTF8String 및 UniversalString 중에서 선택 가능하다. UTF8String 인코딩[RFC 2279]이 기본 인코딩이며, 2003년 12월 31일 이후에 발급된 모든 인증서는 DirectoryString의 UTF8String 인코딩을 사용해야 한다(아래에 언급된 경우 제외). 
    
CA는 위의 날짜까지 DN(고유 이름)을 만들 때 다음 옵션 중에서 선택해야 한다. 

    1.  문자 집합이 충분하면 PrintableString 문자열 사용 가능   
    2. (1)이 불가능하고, BMPString 문자 세트가 충분하면 문자열은 BMPString으로 표현 가능.   
    3. (1), (2)가 불가능하다면, 문자열은 UTF8String으로 표시. (1) 또는 (2)가 충족되는 경우에도 CA는 문자열을 UTF8String으로 표현 가능.   


2003년 12월 31일의 UTF8 인코딩 요구사항의 예외는 아래와 같다.

    1. CA는 UTF8String 인코딩으로의 순차적인 마이그레이션을 지원하기 위해 "name rollover" 인증서를 발급할 수 있다.  이러한 인증서는 발급자로서 CA의 UTF8String 인코딩 이름과 주체로서 이전 이름 인코딩을 포함하거나 그 반대의 경우를 포함할 수 있다.
    2. 섹션 4.1.2.6에 명시된  바와 같이, 주체(subject) 필드는 인코딩에 관계없이 주체 CA에 의해 발급된 모든 인증서의 발급자 필드 내용과 일치하는 고유 이름이 명시되어야 한다.

TeletexString, UniversalString은 이전 버전과의 호환성을 위해 포함되어 있으며 새로운 주체의 인증서에는 사용해서는 안된다. 그러나 이러한 유형은 이전에 이름이 설정된 인증서에서 사용될 수 있다. 인증서 사용자는 이러한 유형의 인증서를 받을 수 있어 대비해야 한다.

또한 많은 레거시 구현체들은 ISO 8859-1 문자 집합(Latin1String)[ISO 8859-1]으로 인코딩된 이름을 지원하지만 TeletexString로 태그를 지정한다. TeletexString은 ISO 8859-1보다 큰 문자 집합을 인코딩하지만 일부 문자를 다르게 인코딩한다. 따라서 두 인코딩 모두 처리할 수 있도록 구현해야 한다.

위에서 언급한 바와 같이 구분 이름(distinguished names)은 속성(attributes)으로 구성된다. 이 규격서는 이름에 나타날 수 있는 속성 유형 집합을 제한하지 않는다. 그러나 아래에 정의된 속성 유형 집합을 포함하는 발급자 이름을 가진 인증서를 받기 위해서는 적합한 구현이 준비되어야 한다. 이 사양은 추가 속성 유형에 대한 지원을 권장한다.

표준 속성은 X.500 시리즈 사양[X.520]에서 정의되었다. 이 규격의 구현은 발급자(issuer) 및 주체(subject, 섹션 4.1.2.6) 명칭으로 다음과 같은 표준 속성 유형을 수신할 수 있도록 준비해야 한다.
    
        - country (C)
        - organization (O)
        - organizational-unit (OU)
        - distinguished name qualifier
        - state or province name
        - common name (e.g., "Susan Housley") (CN)
        - serial number

또한, 이 규격의 구현은 발급자 및 주체 이름으로 다음과 같은 표준 속성 유형을 받을 수 있도록 준비되어야 한다.

        - locality
        - title
        - surname
        - given name
        - initials
        - pseudonym
        - generation qualifier (e.g., "Jr.", "3rd", or "IV")

이러한 속성 유형에 대한 구문 및 관련 개체 식별자(OID)는 부록 A의 ASN.1 모듈에 제공된다.

또한, 이 규격의 구현은 [RFC 2247]에 정의된 domainComponent 속성을 수신할 수 있도록 준비해야 한다. DNS(Domain Name System)는 계층적 자원 라벨링 시스템을 제공한다. 이 속성은 DNS 이름과 병렬로 연결된 DN을 사용하려는 조직에 편리한 메커니즘을 제공합니다. 이것은 대체 이름 필드의 dNSName 구성 요소를 대체하는 것이 아니다. 이러한 이름을 DNS 이름으로 변환하는 데는 구현이 필요하지 않다. 이 속성 유형에 대한 구문 및 관련 OID는 부록 A의 ASN.1 모듈에 제공된다.

인증서 사용자는 인증서 경로 검증(Section 6)을 위한 Name chaining을 수행하기 위해서 발급자 고유 이름(DN) 및 주체 고유 이름(섹션 4.1.2.6) 필드를 처리할 준비를 해야 한다. Name chaining은 인증서의 발급자 고유 이름과 CA 인증서의 주체 이름을 일치시킴으로써 수행된다.

이 명세서에는 X.500 시리즈 사양에 지정된 이름 비교 기능의 일부만 요구한다. 
    
이름 비교 규칙을 구현하려면 아래의 적합한 구현이 요구된다:

    1. 서로 다른 타입(예를 들어, PrintableString 및 BMPStrang)으로 인코딩된 속성 값들은 서로 다른 문자열을 나타내는 것으로 가정될 수 있다.

    2. PrintableString이 아닌 유형의 속성 값은 대소문자를 구분한다.(이는 속성 값을 이진 객체로 일치시킬 수 있다.)

    3. PrintableString의 속성 값은 대소문자를 구분하지 않는다.

    4. PrintableString의 속성 값은 선행 및 후행 공백을 제거하고 하나 이상의 연속된 공백 문자의 내부 하위 문자열을 단일 공백으로 변환한 후 비교된다.

인증서 사용자는 이름 비교 규칙을 통해 익숙하지 않은 언어 또는 인코딩을 사용해 발급된 인증서의 유효성을 검사할 수 있다.

또한, 본 명세서의 구현은 이러한 비교 규칙을 사용하여 익숙하지 않은 속성 유형의 name chaining을 처리할 수 있다. 이를 통해 구현체는 발급자 이름에 익숙하지 않은 속성이 있는 인증서를 처리할 수 있다.

X.500 시리즈 사양에 정의된 비교 규칙은 구별되는 이름의 데이터를 인코딩하는 데 사용되는 문자 집합은 서로 관련이 없음을 나타낸다. 인코딩과 관계없이 문자 자체를 비교한다. 이 프로필의 구현에는 X.500 시리즈에 정의된 비교 알고리즘을 사용할 수 있다. 이러한 구현은 위에서 지정된 알고리즘에 의해 인식된 이름 일치 여부 비교의 상위 집합을 인식할 것이다.

4.1.2.5 validity    
인증서 유효 기간은 CA가 인증서 상태에 대한 정보를 유지할 것을 보증하는 시간 간격. 인증서 유효 기간이 시작되는 날짜(notBefore)와 인증서 유효 기간이 끝나는 날짜(notAfter)의 시퀀스로 표시. notBefore 및 notAfter는 모두 UTCime 또는 Generalized Time으로 인코딩 가능하다.

이 프로파일을 준수하는 CA는 항상 인증서 유효 날짜를 2049년까지 UTCTime으로, 2050년 이후의 인증서 유효 날짜는 GeneralizedTime으로 인코딩해야 한다.

인증서의 유효 기간은 notBefore에서 notAfter까지다.

4.1.2.5.1 UTCTime   
범용 시간 유형인 UTCTime은 날짜와 시간을 표현하기 위한 표준 ASN.1 유형이다. UTC 시간은 두 개의 낮은 순서 숫자를 통해 연도를 지정하고 시간은 1분 또는 1초의 정밀도로 지정한다. UTC 시간에는 Z(Zulu 또는 그리니치 표준시) 또는 시차가 포함된다.

이 프로파일의 목적을 위해 UTC 시간 값은 반드시 그리니치 표준시(Zulu)로 표현되어야 하며 초(즉, 시간은 `YYMMDDHHMMSSZ`)를 포함해야 한다.

다음과 같이 연도 필드(YY)를 해석해야 한다:

```
YY가 50보다 크거나 같을 경우, 연도는 19YY로 해석한다. 
YY가 50 미만인 경우에는 그 연도를 20YY로 해석한다.
```

4.1.2.5.2 GeneralizedTime   
일반화된 시간 유형, GeneralizedTime은 가변 정밀 시간 표현을 위한 표준 ASN.1 유형이다. 선택적으로, GeneralizedTime 필드에는 현지 표준시와 그리니치 표준시 사이의 시간 차이가 포함될 수 있다. 

이 프로파일의 목적을 위해, GeneralizedTime 값은 반드시 그리니치 표준시(Zulu)로 표현되어야 하며 초(즉, 시간은 `YYYMMDDHHMSSZ`)를 포함해야 한다. GeneralizedTime 값은 분수 초를 포함해서는 안 된다.

4.1.2.6 subject    
주체 필드는 주체공개키 필드에 저장된 공개키와 연관된 엔티티를 식별한다. 주체 필드 및/또는 subjectAltName extension에 주체 이름이 담길 수 있다. 주체가 CA인 경우(예: 4.2.1.10에서 논의한 기본 제약 조건 확장이 존재하고 cA의 값이 TRUE), 주체 CA가 발행한 모든 인증서에서 발행자 필드의 내용과 일치하는 비공백 고유 이름(DN)으로 주체 필드를 채워야 한다(제4.1.2.4절). 주체가 CRL 발급자인 경우(예를 들어, 4.2.1.3에서 논의된 바와 같이 키 사용 확장이 존재하고 cRLSign의 값이 TRUE인 경우), 주체 필드는 주체 CRL 발급자가 발행한 모든 CRL에서 발급자 필드의 내용(섹션 4.1.2.4)과 일치하는 비어 있지 않은 고유 이름으로 채워져야 한다. 주체 이름 정보가 subjectAltName extension에만 있는 경우(예: 이메일 주소 또는 URI에만 바인딩된 키), 주체 이름은 비어 있는 시퀀스이어야 하고, subjectAltName extension이 중요하다.

주체 필드가 비어 있지 않은 경우 X.500 고유 이름(DN)이 포함되어야 한다. DN은 발급자 이름 필드에서 정의한 대로 하나의 CA에 의해 인증된 각 주체 엔터티에 대해 고유해야 한다. CA는 동일한 주체 엔티티에 동일한 DN을 가진 둘 이상의 인증서를 발급할 수 있다.

주체 이름 필드는 X.501 유형 이름으로 정의된다. 이 필드에 대한 구현 요구사항은 발급자 필드에 대해 정의된 요구사항과 같다(섹션 4.1.2.4). DirectoryString 유형의 속성 값을 인코딩할 때 발급자 필드에 대한 인코딩 규칙을 구현해야 한다. 이 규격의 구현은 발급자 필드에서 필요한 속성 유형이 포함된 주체 이름을 수신할 수 있도록 준비해야 한다. 이러한 속성 유형에 대한 구문 및 관련 개체 식별자(OID)는 부록 A의 ASN.1 모듈에 제공된다. 이 규격의 구현은 이러한 비교 규칙을 사용하여 익숙하지 않은 속성 유형(즉, 이름 체인)을 처리할 수 있다. 이를 통해 제목 이름에 익숙하지 않은 속성이있는 인증서를 처리하도록 구현할 수 있다. 

또한 RFC 822 이름이 주체 고유 이름에 EmailAddress 속성으로 포함되는 레거시 구현이 존재한다. EmailAddress의 속성 값은 IA5String 유형으로, PrintableString 문자 집합의 일부가 아닌 '@' 문자를 포함할 수 있다. EmailAddress 특성 값은 대소문자를 구분하지 않는다(예: "fanfeedback@redsox.com"은 "FANFEEDBACK@REDSOX.COM"와 동일).

전자 메일 주소를 가진 새 인증서를 생성하는 적합한 구현체는 해당 신원을 설명하기 위해 주체 대체 이름 필드(섹션 4.2.1.7, Subject Alternative Name)의 rfc822Name을 사용해야 한다. 기존 구현을 지원하기 위해 EmailAddress 특성을 제목 고유 이름에 동시에 포함하는 것은 권장되지 않지만 허용된다(deprecated but permitted).

4.1.2.7 Subject Public Key Info   
이 필드는 공개 키를 전송하고 키가 사용되는 알고리즘(예: RSA, DSA 또는 Diffie-Hellman)을 식별하는 데 사용된다. 알고리즘은 섹션 4.1.1.2에 명시된 알고리즘 식별자 구조를 사용하여 식별된다.
```
AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm               OBJECT IDENTIFIER,
    parameters              ANY DEFINED BY algorithm OPTIONAL  }
```
지원되는 알고리즘에 대한 객체 식별자와 공개 키 자료(공개 키 및 매개변수) 인코딩 방법은 [PKIXALGS]에 명시되어 있다.

4.1.2.8 Unique Identifiers   
이 필드는 버전이 2 또는 3(섹션 4.1.2.1)인 경우에만 표시되어야 한다. 이 필드는 버전이 1인 경우 나타나면 안된다. 주체 및 발행자 고유 식별자는 시간이 지남에 따라 주체 및/또는 발행자 이름의 재사용 가능성을 처리하기 위해 인증서에 존재한다. 이 프로파일은 이름이 다른 엔티티에 대해 재사용되지 않고 인터넷 인증서가 고유한 식별자를 사용하지 않는 것을 권장한다. 이 프로필을 준수하는 CA는 고유 식별자가 있는 인증서를 생성하면 안 된다. 이 프로필을 준수하는 응용 프로그램은 고유 식별자를 구문 분석할 수 있어야 한다.

4.1.2.9 Extensions   
이 필드는 버전이 3(섹션 4.1.2.1)인 경우에만 표시되어야 한다. 이 필드는 하나 이상의 인증서 확장의 시퀀스로 존재한다. 인터넷 PKI에서의 인증서 확장의 형식과 내용은 섹션 4.2에 정의되어 있다. 

### 4.2 Certificate Extensions   
X.509 v3 인증서에 대해 정의된 Extension 필드는 추가 속성을 사용자 또는 공개 키와 연결하고 인증 계층 구조를 관리하는 방법을 제공한다. X.509 v3 인증서 형식을 사용하면 커뮤니티에서 해당 커뮤니티 고유 정보를 전달할 수 있는 개별적인 확장을 정의할 수 있다. 인증서의 각 확장은 중요할 수도 중요하지 않을 수도 있다. 이 방식을 사용하는 인증서는 인식하지 못하는 중요한 확장이 발생하면 인증서를 거부해야 한다. 그러나 중요하지 않은 확장은 인식되지 않으면 무시 될 수 있다. 다음 절에서는 인터넷 인증서 및 표준 위치에서 정보를 위해 사용되는 권장 확장을 설명한다. 커뮤니티는 추가 확장을 사용 여부를 선택 가능하다. 그러나 일반적인 상황에서의 사용을 방해할 수 있는 인증서의 중요한 확장을 채택할 때는 주의가 필요하다. 

각각의 확장은 OID 및 ASN.1 구조를 포함한다. 인증서에 확장 필드가 포함되면 OID가 필드 extnID로, 해당 ASN.1 인코딩 구조는 옥텟 문자열 extnValue의 값으로 표현된다. 인증서는 특정 확장의 인스턴스를 둘 이상 포함하면 안 된다. 예를 들어 인증서에 하나의 기관 키 식별자 확장만 포함될 수 있다(section 4.2.1.1). 확장에는 기본값이 FALSE인 boolean 타입의 중요 여부값이 포함된다. 각 확장자의 텍스트는 중요 필드에 대해 허용 가능한 값을 지정한다.

적합한 CA는 아래의 확장을 지원해야한다.
- 키 식별자(섹션 4.2.1.1 및 4.2.1.2)
- 기본 제약 조건(섹션 4.2.1.10)
- 키 사용(섹션 4.2.1.3)
- 인증서 정책(섹션 4.2.1.5) 

CA가 주체 필드에 대해 빈 시퀀스가 있는 인증서를 발급하는 경우 CA는 주체 대체 이름 확장을 지원해야 한다(섹션 4.2.1.7). 나머지 확장에 대한 지원은 선택 사항이다. 적합한 CA는 이 사양 내에서 식별되지 않는 확장을 지원할 수 있다: 인증서 발급자는 이러한 확장을 중요한 것으로 표시하면 상호 운용성이 저해 될 수 있으므로 주의해야 한다.

최소한 이 프로필을 준수하는 응용 프로그램은 다음 확장을 인식해야 한다:
- 키 사용(섹션4.2.1.3)
- 인증서 정책(섹션4.2.1.5)
- 주체 대체 이름(섹션4.2.1.7)
- 기본 제약(섹션4.2.1.1)
- 이름 제약(섹션4.2.1.11)
- 정책 제약(섹션4.2.1.12)
- 확장 키 사용(섹션4.2.1.13)
- 금지하는 모든 정책(섹션4.2.1.15)

또한, 이 명세를 준수하는 애플리케이션들은 기관 및 주체 키 식별자(섹션 4.2.1.1 및 4.2.1.2), 정책 매핑(섹션 4.2.1.6) 확장들을 인식해야 한다.

#### 4.2.1  Standard Extensions 
이 절에서는 인터넷 PKI에서 사용하기 위해 [X.509]에서 정의한 표준 인증서 확장을 식별한다. 각 확장은 [X.509]에 정의된 OID와 연관이 있다. 이 OID는 다음과 같이 정의되는 id-ce의 구성원이다:   
`
id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }  
`
 
4.2.1.1  Authority Key Identifier   
`기관 키 식별자 확장`은 인증서에 서명하는 데 사용되는 <b>CA의 개인 키에 대응하는 공개 키를 식별하는 수단</b>을 제공한다. 이 확장은 발행자가 여러 개의 서명 키를 가지고 있는 경우(다중 동시 키 쌍 또는 전환으로 인해) 사용된다. 식별은 키 식별자(발행자의 인증서에 있는 주체 키 식별자) 또는 발행자 이름 및 일련 번호(serial number)에 기초할 수 있다.

authorityKeyIdentifier 확장의 keyIdentifier 필드는 인증 경로 구성을 용이하게하기 위해서 CA로부터 생성된 모든 인증서에 포함되어야 한다. 한 가지 예외가 있는데, CA가 공개 키를 "자체 서명된" 인증서의 형태로 배포하는 경우, 인증 키 식별자가 생략될 수 있다. 자체 서명된 인증서의 서명은 인증서의 주체 공개 키와 연결된 개인 키로 생성된다. (이것은 발행자가 공개 키와 개인 키를 모두 가지고 있음을 증명한다.) 이 경우 주체 및 기관 키 식별자는 동일하지만 인증 경로 작성에는 주체 키 식별자만 필요하다. 

keyIdentifier 필드의 값은 인증서의 서명을 확인하는 데 사용되는 공용 키 또는 고유한 값을 생성하는 방법에서 파생되어야 한다. 공개 키에서 키 식별자를 생성하는 두 가지 일반적인 방법과 고유한 값을 생성하는 한 가지 일반적인 방법은 Section 4.2.1.2에 설명되어 있다. 키 식별자가 이전에 설정되지 않은 경우, 이 규격은 키 식별자를 생성하기 위해 이러한 방법 중 하나를 사용할 것을 권장한다. 키 식별자가 이전에 설정된 경우, CA는 이전에 설정된 식별자를 사용해야 한다.

이 명세는 모든 인증서 사용자가 키 식별자 방법을 지원할 것을 권장한다.

이 확장은 중요하다고 표시해서는 안 된다.   
```
id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

AuthorityKeyIdentifier ::= SEQUENCE {
    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

KeyIdentifier ::= OCTET STRING
```

4.2.1.2  Subject Key Identifier   
주체 키 식별자 확장은 특정 공개 키를 포함하는 인증서를 식별하는 수단을 제공한다.

인증 경로 구축을 용이하게 하기 위해, 이 확장은 모든 CA 인증서, 즉 CA의 값이 TRUE인 기본 제약 확장(Section 4.2.1.10)을 포함한 모든 인증서에 나타나야 한다. 주체 키 식별자의 값은 이 인증서의 주체가 발급한 인증서의 기관 키 식별자 확장(Section 4.2.1.1)의 키 식별자 필드에 배치된 값이어야 한다. CA 인증서의 경우 주체 키 식별자는 공개 키 또는 고유한 값을 생성하는 방법에서 파생되어야 한다. 

공개 키에서 키 식별자를 생성하는 두 가지 일반적인 방법은 아래와 같다.   
1. keyIdentifier는 BIT STRING subjectPublicKey 값의 160비트 SHA-1 해시로 구성
2. keyIdentifier는 4비트 타입 필드 값 0100 다음에 오는 BIT STRING subjectPublicKey 값의 SHA-1 해시 중 최하위 60비트로 구성

고유한 값을 생성하기 위한 한 가지 일반적인 방법은 단조롭게 증가하는 정수 시퀀스 사용이다.

end entity 인증서의 경우 주체 키 식별자 확장은 응용 프로그램에 사용되는 특정 공개 키가 포함된 인증서를 식별하는 수단을 제공한다. end entity가 특히 다수의 CA로부터 다수의 인증서를 획득한 경우, 주체 키 식별자는 특정 공개 키를 포함하는 인증서 집합를 신속하게 식별할 수 있는 수단을 제공한다. 응용 프로그램이 적절한 end entity 인증서를 식별하는 데 도움이 되도록 이 확장 기능을 모든 end entity 인증서에 포함해야 한다.

end entity 인증서의 경우 주체 키 식별자는 공개 키에서 파생되어야 한다. 공개 키로부터 키 식별자를 생성하기 위한 두 가지 일반적인 방법은 상기와 같다.

키 식별자가 이전에 설정되지 않은 경우, 이 규격은 키 식별자를 생성하기 위해 상기의 방법 중 하나를 사용할 것을 권장한다. 키 식별자가 이전에 설정된 경우 CA는 이전에 설정된 식별자를 사용해야 한다.

이 확장은 중요하다고 표시해서는 안 된다. 

```
id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 } 

SubjectKeyIdentifier ::= KeyIdentifier
```

