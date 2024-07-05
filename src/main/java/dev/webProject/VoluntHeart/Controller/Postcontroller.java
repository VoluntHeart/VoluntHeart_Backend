package dev.webProject.VoluntHeart.Controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import dev.webProject.VoluntHeart.DTO.PostDataDTO;
import dev.webProject.VoluntHeart.DTO.PostsDTO;
import dev.webProject.VoluntHeart.DTOmapper.PostsDTOmapper;
import dev.webProject.VoluntHeart.Exception.UserException;
import dev.webProject.VoluntHeart.Models.Comment;
import dev.webProject.VoluntHeart.Models.Posts;
import dev.webProject.VoluntHeart.Models.Users.UserModel;
import dev.webProject.VoluntHeart.Response.ApiResponse;
import dev.webProject.VoluntHeart.Service.PostService;
import dev.webProject.VoluntHeart.Service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Controller
@RequestMapping("/api/posts")
public class Postcontroller {

    @Autowired
    private PostService postService;

    @Autowired
    private UserService userService;


    //get all posts
    @GetMapping("/all")
    public ResponseEntity<List<PostsDTO>> getAllPosts( @RequestHeader("Authorization") String jwt) {
        
        UserModel user = userService.findByJwtToken(jwt);

        List<Posts> allPosts = postService.allPosts();
        List<PostsDTO> allPostsDTO = PostsDTOmapper.toListOfPostDTOs(allPosts, user);

        return new ResponseEntity<>(allPostsDTO,HttpStatus.OK);

    }

    //get users all posts
    @GetMapping("/users/{userSecret}")
    public ResponseEntity<List<PostsDTO>> getUserAllPosts(@PathVariable String userSecret, @RequestHeader("Authorization") String jwt) {
        
        UserModel reqUser = userService.findByJwtToken(jwt);
        UserModel user = userService.findByUniqueKey(userSecret);

        List<Posts> allPosts = user.getPostsIds();

        List<PostsDTO> allPostsDTO = PostsDTOmapper.toListOfPostDTOs(allPosts, reqUser);

        return new ResponseEntity<>(allPostsDTO,HttpStatus.OK);

    }

    //get user liked posts
    @GetMapping("/user/likes/{userSecret}")
    public ResponseEntity<List<PostsDTO>> getUserLikedPosts(@PathVariable String userSecret, @RequestHeader("Authorization") String jwt) {
        
        UserModel reqUser = userService.findByJwtToken(jwt);
        UserModel user = userService.findByUniqueKey(userSecret);

        List<Posts> allPosts = user.getLikedPosts();
        List<PostsDTO> allPostsDTO = PostsDTOmapper.toListOfPostDTOs(allPosts, reqUser);

        return new ResponseEntity<>(allPostsDTO,HttpStatus.OK);

    }


    //create post
    @PostMapping("/create")
    public ResponseEntity<PostsDTO> createPost(@RequestBody PostDataDTO payload, @RequestHeader("Authorization") String jwt) {


        UserModel creator = userService.findByJwtToken(jwt);
        Posts newPost = postService.createPosts(payload, creator);

        PostsDTO postsDTO = PostsDTOmapper.mapToPostsDTO(newPost, creator);
        return new ResponseEntity<>(postsDTO, HttpStatus.CREATED);

        
    }

  
@GetMapping("/search/{keyword}")
public ResponseEntity<List<PostsDTO>> searchByContent(@PathVariable String keyword, @RequestHeader("Authorization") String jwt){
   
    UserModel reqUser = userService.findByJwtToken(jwt);
    List<Posts> postsWithKeyword= postService.findbyContent(keyword);

    List<PostsDTO> postDTOsWithKeyword = PostsDTOmapper.toListOfPostDTOs(postsWithKeyword, reqUser);

    return new ResponseEntity<>(postDTOsWithKeyword,HttpStatus.ACCEPTED);
  }

    //delete post
    @DeleteMapping("delete/{uniqueKey}")
    public ResponseEntity<ApiResponse> deletePosts(@PathVariable String uniqueKey, @RequestHeader("Authorization") String jwt) throws UserException {
      
       
        UserModel deleteRequestor = userService.findByJwtToken(jwt);
        postService.deletePost(uniqueKey, deleteRequestor.getUserSecret());

        ApiResponse response = new ApiResponse("Successfully Deleted !", true);

        return new ResponseEntity<>(response, HttpStatus.OK);

    }


    @GetMapping("find/{postId}")
    public ResponseEntity<Posts> getbyId(@PathVariable String postId){
      
        Posts p = postService.findByID(postId);
        return new ResponseEntity<>(p,HttpStatus.OK);
    }
    
    //add comments
    @PostMapping("add/comment")
    public ResponseEntity<Comment> addComments(@RequestBody Comment reqComment, @RequestHeader("Authorization") String jwt){

        UserModel user = userService.findByJwtToken(jwt);
       Comment comment = postService.createComment(reqComment, user);

       
        return new ResponseEntity<>(comment,HttpStatus.CREATED);




    }
 
}
