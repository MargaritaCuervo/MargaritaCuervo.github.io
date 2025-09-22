/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.5.27-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: Libros
-- ------------------------------------------------------
-- Server version	10.5.27-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `Autor`
--

DROP TABLE IF EXISTS `Autor`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Autor` (
  `id_autor` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `nacionalidad` varchar(50) DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  PRIMARY KEY (`id_autor`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Autor`
--

LOCK TABLES `Autor` WRITE;
/*!40000 ALTER TABLE `Autor` DISABLE KEYS */;
INSERT INTO `Autor` VALUES (1,'Gabriel García Márquez','Colombia','1927-03-06'),(2,'Isabel Allende','Chile','1942-08-02'),(3,'Mario Vargas Llosa','Perú','1936-03-28'),(4,'Julio Cortázar','Argentina','1914-08-26'),(5,'Jorge Luis Borges','Argentina','1899-08-24'),(6,'Carlos Fuentes','México','1928-11-11'),(7,'Octavio Paz','México','1914-03-31'),(8,'Pablo Neruda','Chile','1904-07-12'),(9,'Laura Esquivel','México','1950-09-30'),(10,'Juan Rulfo','México','1917-05-16'),(11,'Miguel de Cervantes','España','1547-09-29'),(12,'Federico García Lorca','España','1898-06-05'),(13,'Camilo José Cela','España','1916-05-11'),(14,'J.K. Rowling','Reino Unido','1965-07-31'),(15,'George R.R. Martin','Estados Unidos','1948-09-20'),(16,'Stephen King','Estados Unidos','1947-09-21'),(17,'Haruki Murakami','Japón','1949-01-12'),(18,'Banana Yoshimoto','Japón','1964-07-24'),(19,'Umberto Eco','Italia','1932-01-05'),(20,'Italo Calvino','Italia','1923-10-15');
/*!40000 ALTER TABLE `Autor` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Categoria`
--

DROP TABLE IF EXISTS `Categoria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Categoria` (
  `id_categoria` int(11) NOT NULL,
  `nombre` varchar(50) NOT NULL,
  `descripcion` text DEFAULT NULL,
  PRIMARY KEY (`id_categoria`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Categoria`
--

LOCK TABLES `Categoria` WRITE;
/*!40000 ALTER TABLE `Categoria` DISABLE KEYS */;
INSERT INTO `Categoria` VALUES (1,'Novela','Narración extensa en prosa'),(2,'Cuento','Narración breve en prosa'),(3,'Poesía','Obra literaria en verso'),(4,'Ensayo','Texto argumentativo sobre un tema'),(5,'Teatro','Obra dramática'),(6,'Historia','Obras históricas'),(7,'Biografía','Narración de vida de una persona'),(8,'Ciencia Ficción','Narración futurista o tecnológica'),(9,'Fantasía','Narración de mundos imaginarios'),(10,'Misterio','Obras de intriga o suspenso'),(11,'Romance','Narraciones amorosas'),(12,'Aventura','Obras con viajes y hazañas'),(13,'Terror','Obras con elementos de horror'),(14,'Crónica','Relatos periodísticos o históricos'),(15,'Filosofía','Obras de pensamiento crítico'),(16,'Política','Textos relacionados con política'),(17,'Psicología','Obras de análisis de la mente'),(18,'Educación','Textos pedagógicos'),(19,'Economía','Obras sobre economía'),(20,'Arte','Obras relacionadas con artes visuales o escénicas');
/*!40000 ALTER TABLE `Categoria` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Editorial`
--

DROP TABLE IF EXISTS `Editorial`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Editorial` (
  `id_editorial` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `pais` varchar(50) DEFAULT NULL,
  `anio_fundacion` int(11) DEFAULT NULL,
  PRIMARY KEY (`id_editorial`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Editorial`
--

LOCK TABLES `Editorial` WRITE;
/*!40000 ALTER TABLE `Editorial` DISABLE KEYS */;
INSERT INTO `Editorial` VALUES (1,'Penguin Random House','Estados Unidos',1925),(2,'HarperCollins','Estados Unidos',1989),(3,'Simon & Schuster','Estados Unidos',1924),(4,'Macmillan Publishers','Reino Unido',1843),(5,'Hachette Livre','Francia',1826),(6,'Grupo Planeta','España',1949),(7,'Alfaguara','España',1964),(8,'Tusquets Editores','España',1969),(9,'Fondo de Cultura Económica','México',1934),(10,'Anagrama','España',1969),(11,'Editorial Norma','Colombia',1960),(12,'Editorial Sudamericana','Argentina',1939),(13,'Santillana','España',1960),(14,'Siglo XXI Editores','México',1965),(15,'Seix Barral','España',1911),(16,'Editorial Porrúa','México',1900),(17,'Editorial Trillas','México',1959),(18,'Ediciones Paidós','España',1945),(19,'Editorial Minotauro','España',1955),(20,'Editorial Ariel','España',1942);
/*!40000 ALTER TABLE `Editorial` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Libro`
--

DROP TABLE IF EXISTS `Libro`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Libro` (
  `id_libro` int(11) NOT NULL AUTO_INCREMENT,
  `isbn` varchar(20) NOT NULL,
  `titulo` varchar(150) NOT NULL,
  `id_autor` int(11) NOT NULL,
  `id_categoria` int(11) NOT NULL,
  `id_editorial` int(11) NOT NULL,
  `anio_publicacion` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `stock` int(11) NOT NULL,
  `formato` varchar(50) NOT NULL,
  PRIMARY KEY (`id_libro`),
  KEY `id_autor` (`id_autor`),
  KEY `id_categoria` (`id_categoria`),
  KEY `id_editorial` (`id_editorial`),
  CONSTRAINT `Libro_ibfk_1` FOREIGN KEY (`id_autor`) REFERENCES `Autor` (`id_autor`),
  CONSTRAINT `Libro_ibfk_2` FOREIGN KEY (`id_categoria`) REFERENCES `Categoria` (`id_categoria`),
  CONSTRAINT `Libro_ibfk_3` FOREIGN KEY (`id_editorial`) REFERENCES `Editorial` (`id_editorial`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Libro`
--

LOCK TABLES `Libro` WRITE;
/*!40000 ALTER TABLE `Libro` DISABLE KEYS */;
INSERT INTO `Libro` VALUES (1,'978-0-123456-01-1','Introducción a la Inteligencia Artificial',1,1,1,2021,35.50,15,'Tapa dura'),(2,'978-0-123456-01-2','Historia Universal',2,2,2,2019,28.99,8,'Tapa blanda'),(3,'978-0-123456-01-3','El Viaje del Programador',3,1,3,2020,42.00,12,'Digital'),(4,'978-0-123456-01-4','Cocina Mediterránea',4,3,4,2018,22.50,20,'Tapa blanda'),(5,'978-0-123456-01-5','Programación en C++',3,1,5,2022,55.00,10,'Tapa dura'),(6,'978-0-123456-01-6','La Segunda Guerra Mundial',2,2,6,2017,30.00,7,'Tapa dura'),(7,'978-0-123456-01-7','Diseño UX/UI',5,1,7,2023,48.75,18,'Digital'),(8,'978-0-123456-01-8','Matemáticas Aplicadas',6,4,8,2016,27.80,6,'Tapa dura'),(9,'978-0-123456-01-9','El Poder de la Mente',7,5,9,2015,19.90,14,'Tapa blanda'),(10,'978-0-123456-02-0','Redes de Computadoras',3,1,1,2020,60.00,9,'Tapa dura'),(11,'978-0-123456-02-1','Literatura Clásica',8,2,2,2014,15.00,25,'Tapa blanda'),(12,'978-0-123456-02-2','Física Moderna',9,4,3,2021,45.20,11,'Digital'),(13,'978-0-123456-02-3','Arte Contemporáneo',10,6,4,2019,33.10,5,'Tapa dura'),(14,'978-0-123456-02-4','Marketing Digital',11,7,5,2022,39.95,13,'Digital'),(15,'978-0-123456-02-5','Psicología Positiva',12,5,6,2018,25.60,16,'Tapa blanda'),(16,'978-0-123456-02-6','Economía Global',13,9,7,2020,41.70,10,'Tapa dura'),(17,'978-0-123456-02-7','Java para Principiantes',3,1,8,2023,50.00,22,'Digital'),(18,'978-0-123456-02-8','Ecología y Medio Ambiente',14,4,9,2017,29.40,7,'Tapa dura'),(19,'978-0-123456-02-9','Poesía Latinoamericana',15,3,1,2016,18.00,30,'Tapa blanda'),(20,'978-0-123456-03-0','Big Data y Analítica',5,1,2,2021,65.00,12,'Digital');
/*!40000 ALTER TABLE `Libro` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Users`
--

DROP TABLE IF EXISTS `Users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Users`
--

LOCK TABLES `Users` WRITE;
/*!40000 ALTER TABLE `Users` DISABLE KEYS */;
INSERT INTO `Users` VALUES (1,'libro_user2','$pbkdf2-sha256$29000$w7jX2lurFYKw1trbe4.x1g$GaeBujRkjXyhSPdqusMvo6U9337c8/xkNd9Dzl1hPgI'),(2,'libro_user3','$pbkdf2-sha256$29000$cS5lrJWy9r4XgvA.hxBi7A$VZztiRx3LSKB1BUUSJZ08AbqOUNa28617xOOxKCcpRY');
/*!40000 ALTER TABLE `Users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-09-22  3:50:00
