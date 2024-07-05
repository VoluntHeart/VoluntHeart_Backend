package dev.webProject.VoluntHeart.ChatServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    @Autowired
    private MessageService talkJSService;

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteMessage(@RequestBody Message request) {
        return talkJSService.deleteMessage(request.getConversationId());
    }
}
