import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class passwordGenerator {
	public static void main(String[] args) {
		
		System.out.println("1. Generate Password \n2. Exit Program");
		Scanner optionScanner = new Scanner(System.in);
		int optionInput = optionScanner.nextInt();

		if(optionInput == 2){
				int status = 1;
				System.exit(status);}
		
		else if(optionInput == 1) {
			
			int chosenLength = 8;
			while(true){
				
				System.out.println("input password length (minimum 7)");
				Scanner passwordScanner = new Scanner(System.in);
				chosenLength = passwordScanner.nextInt();
				
				if(chosenLength < 7) {
					System.out.println("minimum is 7 characters for a secure password");
				}
				else {
				break;
				}
			}
			
			
			String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
			ArrayList<String> password = new ArrayList<String>();
			
			for (int i = 0; i < chosenLength; i++) {
				int randomNumber = ThreadLocalRandom.current().nextInt(0, characters.length());
				char b = characters.charAt(randomNumber);
				String l = String.valueOf(b);
				password.add(l);

			}
		String formattedPassword = password.toString()
			    .replace(",", "")  //remove the commas
			    .replace("[", "")  //remove the right bracket
			    .replace("]", "")  //remove the left bracket
			    .trim();
		System.out.println(formattedPassword);
		}
	}

}
