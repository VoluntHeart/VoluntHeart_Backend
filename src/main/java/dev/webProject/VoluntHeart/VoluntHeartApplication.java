package dev.webProject.VoluntHeart;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@SpringBootApplication
@RestController
@RequestMapping
public class VoluntHeartApplication {

	public static void main(String[] args) {
		SpringApplication.run(VoluntHeartApplication.class, args);

		
	}

	@GetMapping("/api/root")
	public String apiCheck(){
		return "Hi from backend!";
	}

}
