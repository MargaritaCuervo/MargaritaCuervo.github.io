# 🏦 Arquitectura Cloud Híbrida - Aplicación de Banca Móvil

## 📊 Diagrama Arquitectónico

```mermaid
graph TB
    %% Usuario Móvil
    subgraph "📱 Dispositivo Móvil"
        App[App Móvil]
    end
    
    %% CDN y Load Balancer
    subgraph "🌐 Capa de Red"
        CDN[CloudFront CDN]
        ALB[Application Load Balancer]
    end
    
    %% API Gateway y Funciones Serverless
    subgraph "⚡ Capa Serverless (AWS)"
        APIGW[API Gateway]
        Auth[Lambda - Autenticación]
        Trans[Lambda - Transacciones]
        Notif[Lambda - Notificaciones]
        Report[Lambda - Reportes]
    end
    
    %% Base de Datos Híbrida
    subgraph "🗄️ Base de Datos Híbrida"
        RDS[(RDS MySQL - Datos Sensibles)]
        Dynamo[(DynamoDB - Transacciones)]
        Redis[(ElastiCache Redis - Cache)]
    end
    
    %% Servicios de Seguridad
    subgraph "🔒 Seguridad"
        Cognito[Cognito User Pool]
        KMS[KMS - Encriptación]
        WAF[WAF - Protección]
        GuardDuty[GuardDuty - Monitoreo]
    end
    
    %% Servicios de Monitoreo
    subgraph "📊 Monitoreo y Logs"
        CloudWatch[CloudWatch]
        XRay[X-Ray Tracing]
        CloudTrail[CloudTrail]
    end
    
    %% On-Premises (Nube Privada)
    subgraph "🏢 On-Premises (Nube Privada)"
        CoreBanking[Core Banking System]
        Compliance[Compliance Engine]
        Audit[Audit System]
    end
    
    %% Conexiones
    App --> CDN
    CDN --> ALB
    ALB --> APIGW
    
    APIGW --> Auth
    APIGW --> Trans
    APIGW --> Notif
    APIGW --> Report
    
    Auth --> Cognito
    Auth --> RDS
    Trans --> Dynamo
    Trans --> Redis
    Trans --> CoreBanking
    Notif --> SNS
    Report --> RDS
    Report --> CoreBanking
    
    %% Seguridad
    Auth --> KMS
    Trans --> KMS
    RDS --> KMS
    Dynamo --> KMS
    
    %% Monitoreo
    Auth --> CloudWatch
    Trans --> CloudWatch
    APIGW --> CloudTrail
    Auth --> XRay
    Trans --> XRay
    
    %% Conexión Híbrida
    CoreBanking -.->|VPN/Direct Connect| APIGW
    Compliance -.->|VPN/Direct Connect| APIGW
    Audit -.->|VPN/Direct Connect| APIGW
    
    %% Estilos
    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef hybrid fill:#8B4513,stroke:#000,stroke-width:2px,color:#fff
    classDef security fill:#FF0000,stroke:#000,stroke-width:2px,color:#fff
    classDef monitoring fill:#00FF00,stroke:#000,stroke-width:2px,color:#000
    
    class APIGW,Auth,Trans,Notif,Report,Dynamo,Redis,Cognito,KMS,WAF,GuardDuty,CloudWatch,XRay,CloudTrail aws
    class CoreBanking,Compliance,Audit hybrid
    class RDS security
    class CDN,ALB monitoring
```

## 🏗️ Componentes de la Arquitectura

### **1. Capa de Presentación**
- **App Móvil**: Aplicación nativa iOS/Android
- **CDN (CloudFront)**: Distribución global de contenido estático
- **Load Balancer**: Balanceo de carga entre regiones

### **2. Capa Serverless (AWS)**
- **API Gateway**: Punto de entrada único para todas las APIs
- **Lambda Functions**:
  - **Autenticación**: Login, registro, MFA
  - **Transacciones**: Transferencias, pagos, consultas
  - **Notificaciones**: Push, SMS, email
  - **Reportes**: Extractos, análisis, compliance

### **3. Base de Datos Híbrida**
- **RDS MySQL**: Datos sensibles del cliente (on-premises)
- **DynamoDB**: Transacciones y logs (cloud)
- **Redis**: Cache de sesiones y datos frecuentes

### **4. Seguridad**
- **Cognito**: Gestión de usuarios y autenticación
- **KMS**: Encriptación de datos en reposo y tránsito
- **WAF**: Protección contra ataques web
- **GuardDuty**: Detección de amenazas

### **5. Nube Privada (On-Premises)**
- **Core Banking System**: Sistema principal de banca
- **Compliance Engine**: Motor de cumplimiento regulatorio
- **Audit System**: Sistema de auditoría

### **6. Monitoreo y Observabilidad**
- **CloudWatch**: Métricas y logs
- **X-Ray**: Trazabilidad de requests
- **CloudTrail**: Auditoría de API calls

## 🔄 Flujo de Datos

1. **Usuario** accede a la app móvil
2. **CDN** sirve contenido estático
3. **Load Balancer** distribuye tráfico
4. **API Gateway** enruta requests
5. **Lambda Functions** procesan lógica de negocio
6. **Base de Datos** almacena/recupera información
7. **Sistema On-Premises** valida operaciones críticas
8. **Servicios de Seguridad** protegen en cada capa

## 💡 Ventajas de esta Arquitectura

- **Escalabilidad**: Auto-scaling automático con Lambda
- **Seguridad**: Múltiples capas de protección
- **Cumplimiento**: Datos sensibles en infraestructura privada
- **Costos**: Pago por uso en servicios serverless
- **Disponibilidad**: Multi-región con failover automático
- **Flexibilidad**: Híbrida para cumplir requisitos regulatorios

