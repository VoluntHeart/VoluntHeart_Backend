package dev.webProject.VoluntHeart.Models.Users;

import java.util.ArrayList;
import java.util.List;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import dev.webProject.VoluntHeart.ChatServices.Message;
import dev.webProject.VoluntHeart.Models.Location;
import dev.webProject.VoluntHeart.Models.Posts;
import lombok.Data;

@Data
@Document(collection = "users")
public class UserModel {

    @Id
    String userId;

    String userSecret;
    String email;
    String password;
    String fullName;
    String website;
    String mobile;
    String about;
    String profilePic;
    String coverImage;
    
    boolean donor;
    Location userLocation;
    private boolean googleLogin;
    String googleId;

    @DocumentReference
    @JsonIgnore
    List<Posts> postsIds = new ArrayList<>();

    @DocumentReference
    List<Posts> likedPosts = new ArrayList<>();

    @DocumentReference
    List<UserModel> followers = new ArrayList<>();
    @DocumentReference
    List<UserModel> followings = new ArrayList<>();

    List<Message> chatList = new ArrayList<>();

}
