package dev.webProject.VoluntHeart.Models;

import java.time.LocalDateTime;
import lombok.Data;


@Data
public class Comment {

    private String comment;
    private String postKey;
    private String userKey;
    private String userName;
    private LocalDateTime commentAt;
    
}
