import java.awt.List;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.LinkedList;
import java.util.Random;

public abstract class  AcoesResposta {
	
	public static void mostrarAcoes() {

		LinkedList<String> alertas = analisarArquivo();
		System.out.println(alertas);
		System.out.println("Para os seguintes ataques registrados :");
		for(String a : alertas) {
			System.out.println(a);
		}
		System.out.println("");
		System.out.println("O seguinte plano de contigencia foi feito:");
		LinkedList<String> planos = analisarAcoes(alertas);
		for(String p : planos) {
			System.out.println(p);
		}
		
	}
	private static LinkedList<String> analisarAcoes(LinkedList<String> alertas) {
		LinkedList<String> respostas = new LinkedList<>();
		
		for(String a : alertas) {
			respostas.add(retornarMedida(a));
		}
		
		return respostas;
	}
	private static LinkedList<String> analisarArquivo() {
		
		String caminhoArquivo = "C:\\Users\\edils_wi4z5h7\\Projetos\\tamae\\Auditoria\\logs\\alerts.log";
		//arquivo dos logs
		LinkedList<String> alertas = new LinkedList<>();
		try(BufferedReader reader= new BufferedReader(new FileReader(caminhoArquivo))) {
			String linha;
			
			
			while((linha = reader.readLine()) != null) {
				String[] l1 = linha.split("ALERT: ");
				
				String[] l2 = l1[1].split(" ");
				if(l2[1].startsWith("(")) {
					alertas.add(l2[0]+l2[1]+l2[2]);
				}else {
					alertas.add(l2[0]+l2[1]);
				}
				
				
			}
			
		}catch(Exception e) {
			System.out.println("ERROR "+e.getMessage());
		}
		return alertas;
	}
	
	private static String retornarMedida(String ataque) {
		String medida = "";
		
		if(ataque.equals("SQLInjection")) {
			int random = new Random().nextInt()%5;
			medida = AcoesLista.sorteioSQL(Math.abs(random));
			
		}else if(ataque.equals("SSHBrute")){
			int random = new Random().nextInt()%5;
			medida = AcoesLista.sorteioSSH(Math.abs(random));
			
		}else if(ataque.equals("DataExfiltration")){
			int random = new Random().nextInt()%5;
			medida = AcoesLista.sorteioDataExfiltration(Math.abs(random));
			
		}else if(ataque.equals("PhishingEmail")){
			int random = new Random().nextInt()%5;
			medida = AcoesLista.sorteioEmail(Math.abs(random));
			
		}else if(ataque.equals("Ransomware(fileencryption)")){
			int random = new Random().nextInt()%6;
			medida = AcoesLista.sorteioRansomware(Math.abs(random));		
		}
		return medida;
	}
	
	
	
}
