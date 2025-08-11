# 🏦 Arquitectura de Banca Móvil con Nube Híbrida y Serverless

## 📋 Descripción del Proyecto

Este proyecto implementa una arquitectura cloud híbrida para una aplicación de banca móvil utilizando servicios serverless de AWS y sistemas on-premises. La solución combina la escalabilidad de la nube pública con la seguridad y cumplimiento de sistemas bancarios tradicionales.

## 🏗️ Arquitectura

### Diagrama Arquitectónico
El diagrama completo se encuentra en `arquitectura_banca_movil.md` con la representación visual en Mermaid.

### Componentes Principales

#### 🌐 Capa de Red
- **CloudFront CDN**: Distribución global de contenido estático
- **Application Load Balancer**: Balanceo de carga y routing de tráfico

#### ⚡ Capa Serverless (AWS)
- **API Gateway**: Punto de entrada único para todas las APIs
- **Lambda Functions**:
  - Autenticación: Manejo de usuarios y JWT
  - Transacciones: Procesamiento de operaciones bancarias
  - Notificaciones: Envío de alertas y confirmaciones
  - Reportes: Generación de estados y análisis

#### 🗄️ Base de Datos Híbrida
- **RDS MySQL**: Almacenamiento de datos sensibles y transaccionales
- **DynamoDB**: Base de datos NoSQL para transacciones de alta frecuencia
- **ElastiCache Redis**: Cache en memoria para optimización de rendimiento

#### 🔒 Seguridad
- **Cognito User Pool**: Gestión de usuarios y autenticación
- **KMS**: Encriptación de datos sensibles
- **WAF**: Protección contra ataques web
- **GuardDuty**: Monitoreo de amenazas

#### 📊 Monitoreo y Observabilidad
- **CloudWatch**: Métricas y logs centralizados
- **X-Ray**: Trazabilidad de requests
- **CloudTrail**: Auditoría de API calls

#### 🏢 On-Premises (Nube Privada)
- **Core Banking System**: Sistema principal de banca
- **Compliance Engine**: Motor de cumplimiento regulatorio
- **Audit System**: Sistema de auditoría

## 🚀 Despliegue

### Prerrequisitos
- AWS CLI configurado
- AWS SAM CLI instalado
- Python 3.8+
- Acceso a servicios AWS

### Instalación

1. **Clonar el repositorio**:
```bash
git clone <repository-url>
cd Tarea3_P1
```

2. **Instalar dependencias**:
```bash
pip install -r requirements.txt
```

3. **Configurar variables de entorno**:
```bash
# Crear archivo env.json con configuración local
{
  "Environment": "dev",
  "DatabaseHost": "localhost",
  "DatabaseName": "banking_dev",
  "DatabaseUser": "admin",
  "DatabasePassword": "password"
}
```

### Despliegue Local

1. **Construir la aplicación**:
```bash
sam build
```

2. **Ejecutar localmente**:
```bash
sam local start-api
```

3. **Probar endpoints**:
```bash
# Autenticación
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password123"}'

# Transacciones
curl -X POST http://localhost:3000/transactions \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100.00, "type": "transfer", "recipient": "123456789"}'
```

### Despliegue en AWS

1. **Desplegar en desarrollo**:
```bash
sam deploy --config-env dev
```

2. **Desplegar en staging**:
```bash
sam deploy --config-env staging
```

3. **Desplegar en producción**:
```bash
sam deploy --config-env prod
```

## 🔧 Configuración

### Variables de Entorno
- `Environment`: Entorno de despliegue (dev/staging/prod)
- `DatabaseHost`: Host de la base de datos
- `DatabaseName`: Nombre de la base de datos
- `DatabaseUser`: Usuario de la base de datos
- `DatabasePassword`: Contraseña de la base de datos

### Configuración de AWS
El archivo `samconfig.toml` contiene la configuración para diferentes entornos:
- **Dev**: Desarrollo local y testing
- **Staging**: Entorno de pre-producción
- **Prod**: Entorno de producción

## 📁 Estructura del Proyecto

```
Tarea3_P1/
├── README.md                           # Este archivo
├── arquitectura_banca_movil.md        # Diagrama arquitectónico
├── backend_serverless.py              # Código backend serverless
├── template.yaml                      # Template AWS SAM
├── requirements.txt                   # Dependencias Python
└── samconfig.toml                    # Configuración SAM
```

## 🧪 Testing

### Ejecutar tests unitarios
```bash
python -m pytest tests/
```

### Testing local de Lambda
```bash
sam local invoke AuthFunction --event events/auth-event.json
sam local invoke TransactionFunction --event events/transaction-event.json
```

## 📊 Monitoreo

### CloudWatch Dashboard
El template incluye un dashboard automático con métricas clave:
- Latencia de API
- Tasa de errores
- Uso de Lambda
- Métricas de base de datos

### Logs y Trazabilidad
- **CloudWatch Logs**: Logs centralizados de todas las funciones
- **X-Ray**: Trazabilidad de requests entre servicios
- **CloudTrail**: Auditoría de todas las operaciones AWS

## 🔒 Seguridad

### Encriptación
- **En tránsito**: TLS 1.2+ para todas las comunicaciones
- **En reposo**: KMS para encriptación de datos sensibles
- **Base de datos**: Encriptación automática de RDS y DynamoDB

### Autenticación y Autorización
- **Cognito**: Gestión de usuarios y sesiones
- **JWT**: Tokens de acceso para APIs
- **IAM**: Roles y políticas granulares

### Cumplimiento
- **PCI DSS**: Para datos de tarjetas de crédito
- **SOC 2**: Certificación de seguridad
- **GDPR**: Protección de datos personales

## 💰 Costos Estimados

### Servicios AWS (por mes)
- **Lambda**: $0.20 por 1M de requests
- **API Gateway**: $3.50 por 1M de requests
- **DynamoDB**: $1.25 por GB-mes
- **RDS**: $0.017 por hora (t3.micro)
- **CloudWatch**: $0.50 por métrica por mes

### Estimación Total
- **Desarrollo**: ~$50-100/mes
- **Staging**: ~$200-500/mes
- **Producción**: ~$1000-5000/mes (dependiendo del volumen)

## 🚨 Troubleshooting

### Problemas Comunes

1. **Error de permisos IAM**:
   - Verificar que el rol de Lambda tenga permisos suficientes
   - Revisar políticas en `template.yaml`

2. **Timeout de Lambda**:
   - Aumentar `Timeout` en la configuración de funciones
   - Optimizar código para reducir tiempo de ejecución

3. **Error de conexión a base de datos**:
   - Verificar configuración de VPC y Security Groups
   - Confirmar credenciales en `env.json`

4. **Error de autenticación**:
   - Verificar configuración de Cognito
   - Revisar JWT token y expiración

### Logs de Debug
```bash
# Ver logs de Lambda
sam logs -n AuthFunction --stack-name banking-mobile-app

# Ver logs de API Gateway
aws logs describe-log-groups --log-group-name-prefix "/aws/apigateway"
```

## 📚 Recursos Adicionales

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Serverless Architecture Patterns](https://aws.amazon.com/serverless/patterns/)

## 🤝 Contribución

1. Fork el proyecto
2. Crear una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 📞 Soporte

Para soporte técnico o preguntas sobre la arquitectura:
- Crear un issue en el repositorio
- Contactar al equipo de desarrollo
- Revisar la documentación de AWS

---

**Nota**: Este es un proyecto de demostración. Para uso en producción, asegúrate de implementar todas las medidas de seguridad y cumplimiento necesarias para tu jurisdicción y regulaciones bancarias aplicables.
