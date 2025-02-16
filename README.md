# Explicação do interface.py

O arquivo **interface.py** apresenta uma aplicação em Python que utiliza **Tkinter** para criar uma interface gráfica e **Matplotlib** para exibir gráficos relacionados à codificação e decodificação de uma mensagem. Abaixo estão os principais pontos do que o código faz:

1. **Entrada de Dados**  
   - Há um campo de texto onde o usuário digita a mensagem que deseja enviar.

2. **Conversão para Binário**  
   - A mensagem é convertida em binário, considerando a codificação extendida (latin-1).

3. **Codificação Manchester**  
   - O binário gerado é transformado usando uma codificação Manchester simples.

4. **Exibição de Gráficos**  
   - Dois gráficos são exibidos:  
     - Um mostrando a forma de onda do sinal binário.  
     - Outro mostrando a forma de onda do sinal codificado em Manchester.

5. **Envio e Recebimento de Dados (Sockets)**  
   - Um botão “Enviar” permite enviar a sequência codificada via socket TCP.  
   - O código também executa um pequeno servidor que fica escutando (na porta 9999) por mensagens recebidas, decodificando a string pelo processo inverso.

6. **Decodificação e Impressão no Console**  
   - Quando o programa recebe dados em Manchester, ele decodifica para binário e tenta reconverter em texto, exibindo as informações no console.

Essas funcionalidades permitem realizar uma comunicação simples (local ou em rede) para demonstrar a forma de onda tanto no envio como no recebimento, ilustrando o processo de formatação, envio, recepção e decodificação dos dados.