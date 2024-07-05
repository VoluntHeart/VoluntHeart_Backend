package dev.webProject.VoluntHeart.ChatServices;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MessageService {

    @Value("${talkjs.appId}")
    private String appId;

    @Value("${talkjs.secretKey}")
    private String secretKey;

    public ResponseEntity<String> deleteMessage(String conversationId) {
        String url = String.format("https://api.talkjs.com/v1/%s/conversations/%s", appId, conversationId);

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + secretKey);
        headers.set("Content-Type", "application/json");

        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.DELETE, entity, String.class);

        return response;
    }
}
