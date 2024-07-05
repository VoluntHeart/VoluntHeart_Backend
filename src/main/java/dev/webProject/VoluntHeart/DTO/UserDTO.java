package dev.webProject.VoluntHeart.DTO;

import java.util.ArrayList;
import java.util.List;
import dev.webProject.VoluntHeart.Models.Location;
import lombok.Data;

@Data
public class UserDTO {

   
    String userId;
    String userSecret;
    String email;
    String fullName;
    String website;
    String mobile;
    String about;
    String profilePic;
    String regNumber;
    String coverImage;
    boolean donor;
    Location userLocation;
    private boolean googleLogin;
    private boolean isFollowed;
    
    private List<UserDTO> followers = new ArrayList<>();
    private List<UserDTO> following = new ArrayList<>();
   

    
    
}
