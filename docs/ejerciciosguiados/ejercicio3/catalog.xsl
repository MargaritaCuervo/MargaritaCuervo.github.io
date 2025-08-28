<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="html" indent="yes"/>

  <xsl:template match="/">
    <html>
      <head>
        <meta charset="UTF-8"/>
        <title>Catálogo de Libros</title>
        <link rel="stylesheet" type="text/css" href="catalog.css"/>
        <style>
          #searchBox {
            width: 50%;
            padding: 8px;
            margin: 15px 0;
            border: 1px solid #aaa;
            border-radius: 5px;
            font-size: 14px;
          }
          table {
            border-collapse: collapse;
            width: 100%;
            font-family: Arial, sans-serif;
          }
          th, td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
          }
          th {
            background: #333;
            color: #fff;
          }
          tr:nth-child(even) {
            background: #f9f9f9;
          }
	</style>
	<script><![CDATA[
  function searchBooks() {
    var input, filter, table, tr, td, i, j, txtValue, found;
    input = document.getElementById("searchBox");
    filter = input.value.toLowerCase();
    table = document.getElementById("booksTable");
    tr = table.getElementsByTagName("tr");

    for (i = 1; i < tr.length; i++) {
      td = tr[i].getElementsByTagName("td");
      found = false;
      for (j = 0; j < td.length; j++) {
        if (td[j]) {
          txtValue = td[j].textContent || td[j].innerText;
          if (txtValue.toLowerCase().indexOf(filter) > -1) {
            found = true;
            break;
          }
        }
      }
      tr[i].style.display = found ? "" : "none";
    }
  }
]]></script>
      </head>
      <body>
        <h2>Catálogo de Libros</h2>
        <input type="text" id="searchBox" onkeyup="searchBooks()" placeholder="Buscar por ISBN, título, autor, género, etc..."/>
        
        <table id="booksTable">
          <tr>
            <th>ISBN</th>
            <th>Título</th>
            <th>Autor</th>
            <th>Año</th>
            <th>Género</th>
            <th>Precio</th>
            <th>Stock</th>
            <th>Formato</th>
          </tr>
          <xsl:for-each select="catalog/book">
            <tr>
              <td><xsl:value-of select="@isbn"/></td>
              <td><xsl:value-of select="title"/></td>
              <td><xsl:value-of select="author"/></td>
              <td><xsl:value-of select="year"/></td>
              <td><xsl:value-of select="genre"/></td>
              <td><xsl:value-of select="price"/></td>
              <td><xsl:value-of select="stock"/></td>
              <td><xsl:value-of select="format"/></td>
            </tr>
          </xsl:for-each>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>

