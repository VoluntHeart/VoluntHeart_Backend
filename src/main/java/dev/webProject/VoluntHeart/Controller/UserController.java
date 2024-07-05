package dev.webProject.VoluntHeart.Controller;

import org.springframework.web.bind.annotation.RestController;
import dev.webProject.VoluntHeart.DTO.UserDTO;
import dev.webProject.VoluntHeart.DTOmapper.UserDTOmapper;
import dev.webProject.VoluntHeart.Models.Users.UserModel;
import dev.webProject.VoluntHeart.Service.UserService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@RequestMapping("/api/user")
public class UserController {

  @Autowired
  private UserService userService;

//get all users
  public ResponseEntity<List<UserModel>> getAllUsers() {
    return new ResponseEntity<List<UserModel>>(userService.allUsers(), HttpStatus.OK);
  }

  //search by name
  @GetMapping("/search/{keyword}")
  public ResponseEntity<List<UserDTO>> searchUsersByName(@PathVariable String keyword){
   
    List<UserModel> usersWithKeyword= userService.findbyFullname(keyword);

    List<UserDTO> userDTOsWithKeyword = UserDTOmapper.toListUserDtos(usersWithKeyword);

    return new ResponseEntity<>(userDTOsWithKeyword,HttpStatus.ACCEPTED);
  }
 

  //get another user profile
  @GetMapping("/get/{userSecret}")
  public ResponseEntity<UserDTO> getUser(@PathVariable String userSecret,@RequestHeader("Authorization") String jwt){
    UserModel reqUser = userService.findByJwtToken(jwt);
    UserModel user2 = userService.findByUniqueKey(userSecret);

    UserDTO userDTO_2 = UserDTOmapper.mapToUserDTO(user2);
    boolean followstatus =checkFollowStatus(reqUser, user2);

    userDTO_2.setFollowed(followstatus);
    return new ResponseEntity<UserDTO>(userDTO_2,HttpStatus.ACCEPTED);
  }


// get user profile
  @GetMapping("/profile")
  public ResponseEntity<UserDTO> getUserProfile(@RequestHeader("Authorization") String jwt){
   UserModel reqUser = userService.findByJwtToken(jwt);

    UserDTO userDTO = UserDTOmapper.mapToUserDTO(reqUser);
    return new ResponseEntity<UserDTO>(userDTO,HttpStatus.ACCEPTED);
  }

  //follow user
  @GetMapping("follow/{userSecret}")
  public ResponseEntity<UserDTO> followUserHandling(@PathVariable String userSecret,@RequestHeader("Authorization") String jwt){
    UserModel followRequestor = userService.findByJwtToken(jwt);
    UserModel userTofollow = userService.userFollow(userSecret, followRequestor);
    
    UserDTO usertoFollowDTO = UserDTOmapper.mapToUserDTO(userTofollow);

    boolean followstatus =checkFollowStatus(followRequestor, userTofollow);
    usertoFollowDTO.setFollowed(followstatus);      
   

    return new ResponseEntity<>(usertoFollowDTO,HttpStatus.ACCEPTED);

  }

  //check for follow status
  private boolean checkFollowStatus(UserModel reqUser, UserModel user2) {
  
    return user2.getFollowers().contains(reqUser);
  }

@PostMapping("profile/update")
public ResponseEntity<UserDTO> updateUser(@RequestBody UserModel userData, @RequestHeader("Authorization") String jwt){
  
  System.out.println(userData);
  UserModel updatedUser = userService.updateUser(userData, jwt);
  UserDTO updatedUserDTO = UserDTOmapper.mapToUserDTO(updatedUser);

  return new ResponseEntity<UserDTO>(updatedUserDTO,HttpStatus.ACCEPTED);
}

}
